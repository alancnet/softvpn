package ovpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Key files for control-channel protection, in OpenVPN's formats so keys
// made by "openvpn --genkey" and by softvpn are interchangeable.

// StaticKey is an OpenVPN 2048-bit static key (tls-auth, tls-crypt, and a
// tls-crypt-v2 client key): two halves, each a 64-byte cipher key followed
// by a 64-byte HMAC key.
type StaticKey [256]byte

const (
	staticKeyBegin = "-----BEGIN OpenVPN Static key V1-----"
	staticKeyEnd   = "-----END OpenVPN Static key V1-----"
)

// Key directions (tls-auth FILE [0|1], key-direction).
const (
	KeyDirBidi    = -1 // no direction: both sides use half 0 both ways
	KeyDirNormal  = 0  // send with half 0, receive with half 1 (the server's usual "0")
	KeyDirInverse = 1  // send with half 1, receive with half 0 (the client's "1")
)

// GenerateStaticKey returns a random static key.
func GenerateStaticKey() *StaticKey {
	k := new(StaticKey)
	copy(k[:], randomBytes(len(k)))
	return k
}

// ParseStaticKey reads the "OpenVPN Static key V1" format. Lines outside the
// BEGIN/END markers (the "#" header openvpn writes) are ignored.
func ParseStaticKey(b []byte) (*StaticKey, error) {
	s := string(b)
	i := strings.Index(s, staticKeyBegin)
	j := strings.Index(s, staticKeyEnd)
	if i < 0 || j < i {
		return nil, errors.New("not an OpenVPN static key (missing " + staticKeyBegin + ")")
	}
	h := strings.Join(strings.Fields(s[i+len(staticKeyBegin):j]), "")
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("static key: %v", err)
	}
	if len(raw) != len(StaticKey{}) {
		return nil, fmt.Errorf("static key is %d bits, want 2048", len(raw)*8)
	}
	k := new(StaticKey)
	copy(k[:], raw)
	return k, nil
}

// Marshal encodes the key exactly as "openvpn --genkey secret" does.
func (k *StaticKey) Marshal() []byte {
	var b bytes.Buffer
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n" + staticKeyBegin + "\n")
	for i := 0; i < len(k); i += 16 {
		b.WriteString(hex.EncodeToString(k[i:i+16]) + "\n")
	}
	b.WriteString(staticKeyEnd + "\n")
	return b.Bytes()
}

// half returns the cipher and HMAC keys of half i.
func (k *StaticKey) half(i int) (cipherKey, hmacKey []byte) {
	h := k[i*128 : (i+1)*128]
	return h[:64], h[64:]
}

// halves maps a key direction to the halves used to send and receive.
func halves(dir int) (send, recv int) {
	switch dir {
	case KeyDirNormal:
		return 0, 1
	case KeyDirInverse:
		return 1, 0
	}
	return 0, 0
}

// ---- tls-crypt-v2 ----

// TLSCryptV2ServerKey is the server's tls-crypt-v2 key: a 64-byte cipher key
// and a 64-byte HMAC key, of which AES-256-CTR and HMAC-SHA256 use the first
// 32 bytes each. It wraps (encrypts and authenticates) client keys.
type TLSCryptV2ServerKey [128]byte

const (
	pemV2Server = "OpenVPN tls-crypt-v2 server key"
	pemV2Client = "OpenVPN tls-crypt-v2 client key"

	wkcTagSize  = 32
	wkcMaxLen   = 1024 // TLS_CRYPT_V2_MAX_WKC_LEN
	wkcMinLen   = wkcTagSize + len(StaticKey{}) + 2
	maxMetadata = wkcMaxLen - wkcMinLen // 734 bytes, including the type byte
)

// tls-crypt-v2 metadata types: the first byte of a client key's metadata.
const (
	MetadataUser      = 0x00 // free-form data for tls-crypt-v2-verify
	MetadataTimestamp = 0x01 // 64-bit creation time (openvpn's default)
)

// GenerateTLSCryptV2ServerKey returns a random server key.
func GenerateTLSCryptV2ServerKey() *TLSCryptV2ServerKey {
	k := new(TLSCryptV2ServerKey)
	copy(k[:], randomBytes(len(k)))
	return k
}

// ParseTLSCryptV2ServerKey reads a key from "openvpn --genkey tls-crypt-v2-server".
func ParseTLSCryptV2ServerKey(b []byte) (*TLSCryptV2ServerKey, error) {
	raw, err := decodePEM(b, pemV2Server)
	if err != nil {
		return nil, err
	}
	if len(raw) != len(TLSCryptV2ServerKey{}) {
		return nil, fmt.Errorf("tls-crypt-v2 server key is %d bytes, want 128", len(raw))
	}
	k := new(TLSCryptV2ServerKey)
	copy(k[:], raw)
	return k, nil
}

// Marshal encodes the key as openvpn does.
func (k *TLSCryptV2ServerKey) Marshal() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemV2Server, Bytes: k[:]})
}

func (k *TLSCryptV2ServerKey) ciphers() (cipher.Block, []byte) {
	b, _ := aes.NewCipher(k[:32])
	return b, k[64 : 64+32]
}

// TimestampMetadata is the metadata openvpn puts in a client key by default.
func TimestampMetadata(t time.Time) []byte {
	return binary.BigEndian.AppendUint64([]byte{MetadataTimestamp}, uint64(t.Unix()))
}

// WrapClientKey produces WKc, the client key encrypted and authenticated
// under the server key, which the client sends with its first packet:
//
//	WKc = T || AES-256-CTR(Ke, IV=T[:16], Kc || metadata) || len
//	T   = HMAC-SHA256(Ka, len || Kc || metadata)
//
// where len is the 16-bit length of WKc. metadata starts with its type byte.
func (k *TLSCryptV2ServerKey) WrapClientKey(ck *StaticKey, metadata []byte) ([]byte, error) {
	if len(metadata) > maxMetadata {
		return nil, fmt.Errorf("tls-crypt-v2 metadata too long (%d bytes, max %d)", len(metadata), maxMetadata)
	}
	block, ka := k.ciphers()
	n := wkcMinLen + len(metadata)
	netLen := binary.BigEndian.AppendUint16(nil, uint16(n))
	mac := hmac.New(sha256.New, ka)
	mac.Write(netLen)
	mac.Write(ck[:])
	mac.Write(metadata)
	tag := mac.Sum(nil)

	wkc := make([]byte, 0, n)
	wkc = append(wkc, tag...)
	pt := append(append([]byte(nil), ck[:]...), metadata...)
	ct := make([]byte, len(pt))
	cipher.NewCTR(block, tag[:aes.BlockSize]).XORKeyStream(ct, pt)
	wkc = append(wkc, ct...)
	return append(wkc, netLen...), nil
}

var errWKc = errors.New("tls-crypt-v2: client key does not authenticate under the server key")

// UnwrapClientKey reverses WrapClientKey, returning the client key and its
// metadata.
func (k *TLSCryptV2ServerKey) UnwrapClientKey(wkc []byte) (*StaticKey, []byte, error) {
	if len(wkc) < wkcMinLen || len(wkc) > wkcMaxLen ||
		int(binary.BigEndian.Uint16(wkc[len(wkc)-2:])) != len(wkc) {
		return nil, nil, errors.New("tls-crypt-v2: malformed wrapped client key")
	}
	block, ka := k.ciphers()
	tag, ct, netLen := wkc[:wkcTagSize], wkc[wkcTagSize:len(wkc)-2], wkc[len(wkc)-2:]
	pt := make([]byte, len(ct))
	cipher.NewCTR(block, tag[:aes.BlockSize]).XORKeyStream(pt, ct)
	mac := hmac.New(sha256.New, ka)
	mac.Write(netLen)
	mac.Write(pt)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, nil, errWKc
	}
	ck := new(StaticKey)
	copy(ck[:], pt)
	return ck, pt[len(ck):], nil
}

// NewTLSCryptV2ClientKey generates a client key wrapped by the server key and
// returns it in the format of "openvpn --genkey tls-crypt-v2-client". A nil
// metadata means a creation timestamp, like openvpn.
func (k *TLSCryptV2ServerKey) NewTLSCryptV2ClientKey(metadata []byte) ([]byte, error) {
	if metadata == nil {
		metadata = TimestampMetadata(time.Now())
	}
	ck := GenerateStaticKey()
	wkc, err := k.WrapClientKey(ck, metadata)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemV2Client, Bytes: append(ck[:], wkc...)}), nil
}

// ParseTLSCryptV2ClientKey splits a client key file into Kc and WKc.
func ParseTLSCryptV2ClientKey(b []byte) (*StaticKey, []byte, error) {
	raw, err := decodePEM(b, pemV2Client)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) < len(StaticKey{})+wkcMinLen {
		return nil, nil, errors.New("tls-crypt-v2 client key too short")
	}
	ck := new(StaticKey)
	copy(ck[:], raw)
	return ck, raw[len(ck):], nil
}

func decodePEM(b []byte, typ string) ([]byte, error) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("no %q block found", typ)
		}
		if blk.Type == typ {
			return blk.Bytes, nil
		}
	}
}
