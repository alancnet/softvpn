package ovpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"
)

// WrapMode selects how control packets are protected outside TLS.
type WrapMode int

const (
	WrapNone       WrapMode = iota
	WrapTLSAuth             // tls-auth: HMAC over every control packet
	WrapTLSCrypt            // tls-crypt: AES-256-CTR + HMAC-SHA256, shared key
	WrapTLSCryptV2          // tls-crypt-v2: tls-crypt with a per-client key
)

func (m WrapMode) String() string {
	return [...]string{"none", "tls-auth", "tls-crypt", "tls-crypt-v2"}[m]
}

// ControlWrap configures control-channel protection. Packets that fail it
// are dropped before any session state is created.
type ControlWrap struct {
	Mode      WrapMode
	Key       *StaticKey           // tls-auth, tls-crypt
	Direction int                  // tls-auth key direction (KeyDir*)
	Digest    string               // tls-auth HMAC digest ("auth"); default SHA1
	V2Key     *TLSCryptV2ServerKey // tls-crypt-v2
}

// Digests are the "auth" digests tls-auth supports.
var Digests = map[string]func() hash.Hash{
	"SHA1": sha1.New, "SHA224": sha256.New224, "SHA256": sha256.New,
	"SHA384": sha512.New384, "SHA512": sha512.New,
}

// DigestFunc looks up an "auth" digest name.
func DigestFunc(name string) (func() hash.Hash, error) {
	if name == "" {
		name = "SHA1"
	}
	h, ok := Digests[strings.ToUpper(strings.ReplaceAll(name, "-", ""))]
	if !ok {
		return nil, fmt.Errorf("unsupported digest %q (supported: SHA1, SHA224, SHA256, SHA384, SHA512)", name)
	}
	return h, nil
}

// tlsWrap is one session's control-channel protection: keys, the outgoing
// packet id, and the replay window for incoming packet ids.
//
// tls-auth:  op|sid | HMAC | pid | time | acks... msgid payload
//
//	HMAC = HMAC(pid | time | op | sid | acks... msgid payload)
//
// tls-crypt: op|sid | pid | time | tag (32) | AES-256-CTR(acks... msgid payload)
//
//	tag = HMAC-SHA256(op | sid | pid | time | acks... msgid payload)
//	IV  = tag[:16]
//
// A tls-crypt-v2 client appends its wrapped key (WKc) to
// P_CONTROL_HARD_RESET_CLIENT_V3 and P_CONTROL_WKC_V1 packets.
type tlsWrap struct {
	mode     WrapMode
	hash     func() hash.Hash
	sendHMAC []byte
	recvHMAC []byte
	sendAES  cipher.Block // tls-crypt only
	recvAES  cipher.Block

	sendMu   sync.Mutex
	sendPID  uint32
	sendTime uint32

	recvMu   sync.Mutex
	recvTime uint32
	replay   replayWindow
}

const pidSize = 8 // packet id + net_time

func newTLSWrap(cfg *ControlWrap) (*tlsWrap, error) {
	switch cfg.Mode {
	case WrapTLSAuth:
		h, err := DigestFunc(cfg.Digest)
		if err != nil {
			return nil, err
		}
		send, recv := halves(cfg.Direction)
		n := h().Size()
		_, sk := cfg.Key.half(send)
		_, rk := cfg.Key.half(recv)
		return &tlsWrap{mode: WrapTLSAuth, hash: h, sendHMAC: sk[:n], recvHMAC: rk[:n]}, nil
	case WrapTLSCrypt:
		return newTLSCrypt(cfg.Key, WrapTLSCrypt, KeyDirNormal), nil
	}
	return nil, fmt.Errorf("control-channel wrap %v needs a client key", cfg.Mode)
}

// newTLSCrypt sets up tls-crypt. Unlike tls-auth the direction is fixed by
// role: the server uses 0 (KeyDirNormal) and the client 1.
func newTLSCrypt(k *StaticKey, mode WrapMode, dir int) *tlsWrap {
	send, recv := halves(dir)
	sc, sk := k.half(send)
	rc, rk := k.half(recv)
	w := &tlsWrap{mode: mode, hash: sha256.New, sendHMAC: sk[:32], recvHMAC: rk[:32]}
	w.sendAES, _ = aes.NewCipher(sc[:32])
	w.recvAES, _ = aes.NewCipher(rc[:32])
	return w
}

func (w *tlsWrap) mac(key []byte, parts ...[]byte) []byte {
	m := hmac.New(w.hash, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// wrap protects a marshalled control packet for sending.
func (w *tlsWrap) wrap(plain []byte) []byte {
	w.sendMu.Lock()
	if w.sendTime == 0 {
		w.sendTime = uint32(time.Now().Unix())
	}
	w.sendPID++
	pid := binary.BigEndian.AppendUint32(nil, w.sendPID)
	pid = binary.BigEndian.AppendUint32(pid, w.sendTime)
	w.sendMu.Unlock()

	hdr, body := plain[:9], plain[9:]
	out := make([]byte, 0, len(plain)+pidSize+64)
	out = append(out, hdr...)
	if w.mode == WrapTLSAuth {
		out = append(out, w.mac(w.sendHMAC, pid, hdr, body)...)
		out = append(out, pid...)
		return append(out, body...)
	}
	tag := w.mac(w.sendHMAC, hdr, pid, body)
	out = append(out, pid...)
	out = append(out, tag...)
	ct := make([]byte, len(body))
	cipher.NewCTR(w.sendAES, tag[:aes.BlockSize]).XORKeyStream(ct, body)
	return append(out, ct...)
}

var (
	errWrapAuth   = errors.New("control packet authentication failed")
	errWrapReplay = errors.New("replayed control packet")
)

// unwrap authenticates (and for tls-crypt decrypts) a received control
// packet, checks its packet id for replays, and returns the plain packet.
// Any WKc trailer must already have been removed.
func (w *tlsWrap) unwrap(b []byte) ([]byte, error) {
	var hdr, pid, body []byte
	if w.mode == WrapTLSAuth {
		n := w.hash().Size()
		if len(b) < 9+n+pidSize {
			return nil, errShort
		}
		hdr, pid, body = b[:9], b[9+n:9+n+pidSize], b[9+n+pidSize:]
		if !hmac.Equal(b[9:9+n], w.mac(w.recvHMAC, pid, hdr, body)) {
			return nil, errWrapAuth
		}
	} else {
		if len(b) < 9+pidSize+32 {
			return nil, errShort
		}
		hdr, pid = b[:9], b[9:9+pidSize]
		tag := b[9+pidSize : 9+pidSize+32]
		body = make([]byte, len(b)-9-pidSize-32)
		cipher.NewCTR(w.recvAES, tag[:aes.BlockSize]).XORKeyStream(body, b[9+pidSize+32:])
		if !hmac.Equal(tag, w.mac(w.recvHMAC, hdr, pid, body)) {
			return nil, errWrapAuth
		}
	}
	if !w.acceptPID(binary.BigEndian.Uint32(pid), binary.BigEndian.Uint32(pid[4:])) {
		return nil, errWrapReplay
	}
	return append(append(make([]byte, 0, 9+len(body)), hdr...), body...), nil
}

// acceptPID is OpenVPN's packet-id check for long-form (id, time) ids: a
// newer time starts a new sequence, an older one is rejected, and within
// one time ids pass through the sliding replay window.
func (w *tlsWrap) acceptPID(id, t uint32) bool {
	w.recvMu.Lock()
	defer w.recvMu.Unlock()
	if t < w.recvTime {
		return false
	}
	if t > w.recvTime {
		w.recvTime = t
		w.replay.max, w.replay.bits = 0, 0
	}
	return w.replay.accept(id)
}

// splitWKc removes the wrapped client key that a tls-crypt-v2 client
// appends to P_CONTROL_HARD_RESET_CLIENT_V3 and P_CONTROL_WKC_V1. Its last
// two bytes give its length.
func splitWKc(b []byte) (pkt, wkc []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errShort
	}
	n := int(binary.BigEndian.Uint16(b[len(b)-2:]))
	if n < wkcMinLen || n > len(b)-9 {
		return nil, nil, errors.New("tls-crypt-v2: bad wrapped client key length")
	}
	return b[:len(b)-n], b[len(b)-n:], nil
}

// hasWKc reports whether packets with this opcode carry a WKc trailer.
func hasWKc(op byte) bool { return op == opControlHardResetClientV3 || op == opControlWKCV1 }

// acceptReset checks a client's first packet (a hard reset) against the
// server's control-channel protection before any state is kept for it. It
// returns the new session's wrap state (nil without protection) and the
// plain packet.
func acceptReset(cfg *ControlWrap, b []byte) (*tlsWrap, []byte, error) {
	op := opcodeOf(b[0])
	mode := WrapNone
	if cfg != nil {
		mode = cfg.Mode
	}
	if (op == opControlHardResetClientV3) != (mode == WrapTLSCryptV2) {
		return nil, nil, fmt.Errorf("hard reset opcode %d does not match the server's control-channel mode (%v)", op, mode)
	}
	var w *tlsWrap
	switch mode {
	case WrapNone:
		return nil, b, nil
	case WrapTLSCryptV2:
		pkt, wkc, err := splitWKc(b)
		if err != nil {
			return nil, nil, err
		}
		ck, _, err := cfg.V2Key.UnwrapClientKey(wkc)
		if err != nil {
			return nil, nil, err
		}
		w, b = newTLSCrypt(ck, WrapTLSCryptV2, KeyDirNormal), pkt
	default:
		var err error
		if w, err = newTLSWrap(cfg); err != nil {
			return nil, nil, err
		}
	}
	plain, err := w.unwrap(b)
	if err != nil {
		return nil, nil, err
	}
	return w, plain, nil
}

// unwrapInput turns a received control packet into a plain one.
func (w *tlsWrap) unwrapInput(b []byte) ([]byte, error) {
	op := opcodeOf(b[0])
	if hasWKc(op) {
		if w.mode != WrapTLSCryptV2 {
			return nil, fmt.Errorf("opcode %d without tls-crypt-v2", op)
		}
		var err error
		if b, _, err = splitWKc(b); err != nil {
			return nil, err
		}
	}
	plain, err := w.unwrap(b)
	if err != nil {
		return nil, err
	}
	if op == opControlWKCV1 { // a P_CONTROL_V1 that also carried the WKc
		plain[0] = opControlV1<<3 | keyIDOf(plain[0])
	}
	return plain, nil
}
