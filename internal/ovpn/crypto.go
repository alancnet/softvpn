package ovpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// SupportedCiphers are the AEAD data-channel ciphers, in default preference
// order. They match the OpenVPN 2.6 default data-ciphers.
var SupportedCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}

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

const (
	keySize      = 128 // one direction: 64 bytes cipher key + 64 bytes HMAC key
	keyBlockSize = 2 * keySize
	implicitIV   = 8
	tagSize      = 16
)

// dataKeys holds both directions of the data channel for one key state.
type dataKeys struct {
	send    cipher.AEAD
	sendIV  [implicitIV]byte
	sendPID atomic.Uint32

	recv   cipher.AEAD
	recvIV [implicitIV]byte
	replay replayWindow
}

// newDataKeys splits a 256-byte key block. key[0] protects client->server
// traffic and key[1] server->client. For AEAD ciphers the "HMAC" half of
// each key supplies the implicit part of the nonce.
func newDataKeys(cipherName string, block []byte) (*dataKeys, error) {
	if len(block) != keyBlockSize {
		return nil, errors.New("bad key block size")
	}
	c2s, s2c := block[:keySize], block[keySize:]
	d := &dataKeys{}
	var err error
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
