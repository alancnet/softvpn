package ovpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/chacha20poly1305"
)

// SupportedCiphers are the AEAD data-channel ciphers, in default preference
// order. They match the OpenVPN 2.6 default data-ciphers.
var SupportedCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}

// CBCCiphers are the legacy (pre-AEAD) ciphers, authenticated with an HMAC
// using the "auth" digest. They are for old clients and are only used when
// configured in data-ciphers, data-ciphers-fallback or cipher.
var CBCCiphers = []string{"AES-256-CBC", "AES-192-CBC", "AES-128-CBC", "BF-CBC"}

// CipherSupported reports whether name is a data-channel cipher softvpn
// implements, AEAD or CBC.
func CipherSupported(name string) bool {
	return inList(name, SupportedCiphers) || inList(name, CBCCiphers)
}

func inList(name string, list []string) bool {
	for _, c := range list {
		if strings.EqualFold(c, name) {
			return true
		}
	}
	return false
}

func isCBC(name string) bool { return inList(name, CBCCiphers) }

func newAEAD(name string, key []byte) (cipher.AEAD, error) {
	switch strings.ToUpper(name) {
	case "AES-256-GCM", "AES-128-GCM":
		size := 32
		if strings.HasPrefix(strings.ToUpper(name), "AES-128") {
			size = 16
		}
		b, err := aes.NewCipher(key[:size])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	case "CHACHA20-POLY1305":
		return chacha20poly1305.New(key[:chacha20poly1305.KeySize])
	}
	return nil, fmt.Errorf("unsupported cipher %q", name)
}

// newBlock returns the block cipher of a CBC cipher, keyed with the first
// bytes of key as OpenVPN does (BF-CBC uses its default 128-bit key).
func newBlock(name string, key []byte) (cipher.Block, error) {
	switch strings.ToUpper(name) {
	case "AES-128-CBC":
		return aes.NewCipher(key[:16])
	case "AES-192-CBC":
		return aes.NewCipher(key[:24])
	case "AES-256-CBC":
		return aes.NewCipher(key[:32])
	case "BF-CBC":
		return blowfish.NewCipher(key[:16])
	}
	return nil, fmt.Errorf("unsupported cipher %q", name)
}

const (
	keySize      = 128 // one direction: 64 bytes cipher key + 64 bytes HMAC key
	keyBlockSize = 2 * keySize
	implicitIV   = 8
	tagSize      = 16
)

// dataKeys holds both directions of the data channel for one key state.
type dataKeys struct {
	// AEAD ciphers
	send   cipher.AEAD
	sendIV [implicitIV]byte
	recv   cipher.AEAD
	recvIV [implicitIV]byte

	// CBC ciphers, with HMAC
	sendBlock, recvBlock cipher.Block
	digest               func() hash.Hash
	sendMAC, recvMAC     []byte

	sendPID atomic.Uint32
	replay  replayWindow
}

// newDataKeys splits a 256-byte key block. key[0] protects client->server
// traffic and key[1] server->client; each is a 64-byte cipher key followed
// by a 64-byte HMAC key. For AEAD ciphers the "HMAC" half supplies the
// implicit part of the nonce; CBC ciphers use it for HMAC with the "auth"
// digest.
func newDataKeys(cipherName, auth string, block []byte) (*dataKeys, error) {
	if len(block) != keyBlockSize {
		return nil, errors.New("bad key block size")
	}
	c2s, s2c := block[:keySize], block[keySize:]
	d := &dataKeys{}
	var err error
	if isCBC(cipherName) {
		if d.digest, err = DigestFunc(auth); err != nil {
			return nil, err
		}
		if d.recvBlock, err = newBlock(cipherName, c2s[:64]); err != nil {
			return nil, err
		}
		if d.sendBlock, err = newBlock(cipherName, s2c[:64]); err != nil {
			return nil, err
		}
		n := d.digest().Size()
		d.recvMAC = append([]byte(nil), c2s[64:64+n]...)
		d.sendMAC = append([]byte(nil), s2c[64:64+n]...)
		return d, nil
	}
	if d.recv, err = newAEAD(cipherName, c2s[:64]); err != nil {
		return nil, err
	}
	if d.send, err = newAEAD(cipherName, s2c[:64]); err != nil {
		return nil, err
	}
	copy(d.recvIV[:], c2s[64:])
	copy(d.sendIV[:], s2c[64:])
	return d, nil
}

func nonce(pid []byte, iv [implicitIV]byte) []byte {
	n := make([]byte, 0, 12)
	n = append(n, pid...)
	return append(n, iv[:]...)
}

// seal encrypts plaintext into a data packet. hdr is the opcode byte, plus
// the 3-byte peer id for P_DATA_V2.
//
//	hdr | packet-id (4) | tag (16) | ciphertext
//
// The additional data is hdr||packet-id for V2 and packet-id alone for V1.
func (d *dataKeys) seal(hdr, plaintext []byte) []byte {
	if d.sendBlock != nil {
		return d.sealCBC(hdr, plaintext)
	}
	pid := d.sendPID.Add(1)
	out := make([]byte, 0, len(hdr)+4+tagSize+len(plaintext))
	out = append(out, hdr...)
	out = binary.BigEndian.AppendUint32(out, pid)
	ad := out[len(out)-4:]
	if len(hdr) == 4 {
		ad = out
	}
	pidBytes := out[len(hdr):]
	sealed := d.send.Seal(nil, nonce(pidBytes, d.sendIV), plaintext, ad)
	ct, tag := sealed[:len(plaintext)], sealed[len(plaintext):]
	out = append(out, tag...)
	return append(out, ct...)
}

var errAuth = errors.New("data packet authentication failed")

// open authenticates and decrypts a data packet whose header is hdrLen bytes.
func (d *dataKeys) open(pkt []byte, hdrLen int) ([]byte, error) {
	if d.recvBlock != nil {
		return d.openCBC(pkt, hdrLen)
	}
	if len(pkt) < hdrLen+4+tagSize {
		return nil, errShort
	}
	pidBytes := pkt[hdrLen : hdrLen+4]
	ad := pidBytes
	if hdrLen == 4 {
		ad = pkt[:8]
	}
	tag := pkt[hdrLen+4 : hdrLen+4+tagSize]
	ct := pkt[hdrLen+4+tagSize:]
	buf := make([]byte, 0, len(ct)+tagSize)
	buf = append(append(buf, ct...), tag...)
	pt, err := d.recv.Open(buf[:0], nonce(pidBytes, d.recvIV), buf, ad)
	if err != nil {
		return nil, errAuth
	}
	if !d.replay.accept(binary.BigEndian.Uint32(pidBytes)) {
		return nil, errors.New("replayed data packet")
	}
	return pt, nil
}

// sealCBC is the non-AEAD data channel format:
//
//	hdr | HMAC(IV || ciphertext) | IV | CBC(packet-id (4) || plaintext || PKCS#7 padding)
//
// Unlike the AEAD format, the opcode and peer id are not authenticated.
func (d *dataKeys) sealCBC(hdr, plaintext []byte) []byte {
	bs := d.sendBlock.BlockSize()
	macLen := len(d.sendMAC)
	n := 4 + len(plaintext)
	pad := bs - n%bs
	out := make([]byte, len(hdr)+macLen+bs+n+pad)
	copy(out, hdr)
	iv := out[len(hdr)+macLen : len(hdr)+macLen+bs]
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	body := out[len(hdr)+macLen+bs:]
	binary.BigEndian.PutUint32(body, d.sendPID.Add(1))
	copy(body[4:], plaintext)
	for i := n; i < len(body); i++ {
		body[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(d.sendBlock, iv).CryptBlocks(body, body)
	mac := hmac.New(d.digest, d.sendMAC)
	mac.Write(out[len(hdr)+macLen:])
	copy(out[len(hdr):], mac.Sum(nil))
	return out
}

func (d *dataKeys) openCBC(pkt []byte, hdrLen int) ([]byte, error) {
	bs := d.recvBlock.BlockSize()
	macLen := len(d.recvMAC)
	if len(pkt) < hdrLen+macLen+2*bs {
		return nil, errShort
	}
	mac := hmac.New(d.digest, d.recvMAC)
	mac.Write(pkt[hdrLen+macLen:])
	if !hmac.Equal(mac.Sum(nil), pkt[hdrLen:hdrLen+macLen]) {
		return nil, errAuth
	}
	iv := pkt[hdrLen+macLen : hdrLen+macLen+bs]
	ct := pkt[hdrLen+macLen+bs:]
	if len(ct)%bs != 0 {
		return nil, errors.New("CBC ciphertext is not a whole number of blocks")
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(d.recvBlock, iv).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad == 0 || pad > bs || pad > len(pt)-4 {
		return nil, errors.New("bad CBC padding")
	}
	for _, b := range pt[len(pt)-pad:] {
		if int(b) != pad {
			return nil, errors.New("bad CBC padding")
		}
	}
	if !d.replay.accept(binary.BigEndian.Uint32(pt)) {
		return nil, errors.New("replayed data packet")
	}
	return pt[4 : len(pt)-pad], nil
}

// replayWindow is a 64-packet sliding window over data-channel packet ids.
type replayWindow struct {
	mu   sync.Mutex
	max  uint32
	bits uint64
}

func (w *replayWindow) accept(pid uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if pid == 0 {
		return false
	}
	if pid > w.max {
		shift := pid - w.max
		if shift >= 64 {
			w.bits = 0
		} else {
			w.bits <<= shift
		}
		w.bits |= 1
		w.max = pid
		return true
	}
	diff := w.max - pid
	if diff >= 64 || w.bits&(1<<diff) != 0 {
		return false
	}
	w.bits |= 1 << diff
	return true
}

// tls1PRF is the TLS 1.0/1.1 PRF that OpenVPN uses for its legacy key
// derivation: P_MD5(S1, seed) XOR P_SHA1(S2, seed).
func tls1PRF(secret, seed []byte, n int) []byte {
	half := (len(secret) + 1) / 2
	s1, s2 := secret[:half], secret[len(secret)-half:]
	out := pHash(md5.New, s1, seed, n)
	sh := pHash(sha1.New, s2, seed, n)
	for i := range out {
		out[i] ^= sh[i]
	}
	return out
}

func pHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	out := make([]byte, 0, n+64)
	mac := hmac.New(h, secret)
	mac.Write(seed)
	a := mac.Sum(nil)
	for len(out) < n {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		out = mac.Sum(out)
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return out[:n]
}

func prfSeed(label string, parts ...[]byte) []byte {
	seed := []byte(label)
	for _, p := range parts {
		seed = append(seed, p...)
	}
	return seed
}

// openvpnPRFKeys derives the data-channel key block the pre-2.6 way.
func openvpnPRFKeys(preMaster, cRand1, sRand1, cRand2, sRand2 []byte, clientSID, serverSID sessionID) []byte {
	master := tls1PRF(preMaster, prfSeed("OpenVPN master secret", cRand1, sRand1), 48)
	return tls1PRF(master, prfSeed("OpenVPN key expansion", cRand2, sRand2, clientSID[:], serverSID[:]), keyBlockSize)
}

// ekmLabel is the RFC 5705 exporter label for "key-derivation tls-ekm".
const ekmLabel = "EXPORTER-OpenVPN-datakeys"
