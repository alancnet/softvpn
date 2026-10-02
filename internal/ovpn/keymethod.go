package ovpn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// clientKeyMethod2 is the message a client sends over TLS once the
// handshake completes (OpenVPN "key method 2").
type clientKeyMethod2 struct {
	preMaster []byte // 48
	random1   []byte // 32
	random2   []byte // 32
	options   string
	username  string
	password  string
	peerInfo  string
}

var errIncomplete = errors.New("incomplete key method message")

func readString(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, errIncomplete
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < n {
		return "", nil, errIncomplete
	}
	return strings.TrimRight(string(b[:n]), "\x00"), b[n:], nil
}

func appendString(b []byte, s string) []byte {
	if s == "" {
		return binary.BigEndian.AppendUint16(b, 0)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)+1))
	b = append(b, s...)
	return append(b, 0)
}

// parseClientKeyMethod2 parses the client's message. The username, password
// and peer-info fields are optional and only parsed when present.
func parseClientKeyMethod2(b []byte) (*clientKeyMethod2, error) {
	const fixed = 4 + 1 + 48 + 32 + 32
	if len(b) < fixed {
		return nil, errIncomplete
	}
	if binary.BigEndian.Uint32(b) != 0 {
		return nil, errors.New("key method 1 is not supported")
	}
	if b[4]&0x0f != 2 {
		return nil, errors.New("only key method 2 is supported")
	}
	km := &clientKeyMethod2{
		preMaster: append([]byte(nil), b[5:53]...),
		random1:   append([]byte(nil), b[53:85]...),
		random2:   append([]byte(nil), b[85:117]...),
	}
	rest := b[fixed:]
	var err error
	if km.options, rest, err = readString(rest); err != nil {
		return nil, err
	}
	for _, f := range []*string{&km.username, &km.password, &km.peerInfo} {
		if len(rest) == 0 {
			break
		}
		if *f, rest, err = readString(rest); err != nil {
			return nil, err
		}
	}
	return km, nil
}

// serverKeyMethod2 builds the server's reply: random material and options,
// followed by empty username, password and peer-info fields.
func serverKeyMethod2(random1, random2 []byte, options string) []byte {
	b := make([]byte, 5, 128+len(options))
	b[4] = 2
	b = append(b, random1...)
	b = append(b, random2...)
	b = appendString(b, options)
	b = appendString(b, "")
	b = appendString(b, "")
	return appendString(b, "")
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// peerInfo is the parsed IV_* key/value list a client sends.
type peerInfo map[string]string

func parsePeerInfo(s string) peerInfo {
	pi := peerInfo{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			pi[k] = v
		}
	}
	return pi
}

func (pi peerInfo) protoFlags() int {
	n, _ := strconv.Atoi(pi["IV_PROTO"])
	return n
}

const (
	ivProtoDataV2       = 1 << 1
	ivProtoTLSKeyExport = 1 << 3
	ivProtoCCExitNotify = 1 << 7
)

// negotiateCipher picks the first server cipher the client also supports.
func negotiateCipher(server []string, pi peerInfo) (string, bool) {
	var client []string
	if c := pi["IV_CIPHERS"]; c != "" {
		client = strings.Split(c, ":")
	} else if ncp, _ := strconv.Atoi(pi["IV_NCP"]); ncp >= 2 {
		client = []string{"AES-256-GCM", "AES-128-GCM"}
	}
	for _, s := range server {
		for _, c := range client {
			if strings.EqualFold(s, c) {
				return strings.ToUpper(s), true
			}
		}
	}
	return "", false
}

// pipe is the net.Conn that crypto/tls runs over: reads come from the
// reliability layer's in-order TLS bytes, writes go back into it.
type pipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
	write  func([]byte)
}

func newPipe(write func([]byte)) *pipe {
	p := &pipe{write: write}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *pipe) feed(b []byte) {
	p.mu.Lock()
	p.buf = append(p.buf, b...)
	p.mu.Unlock()
	p.cond.Signal()
}

func (p *pipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		p.cond.Wait()
	}
	if len(p.buf) == 0 {
		return 0, net.ErrClosed
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *pipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	p.write(b)
	return len(b), nil
}

func (p *pipe) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.cond.Broadcast()
	return nil
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "openvpn-control" }
func (pipeAddr) String() string  { return "openvpn-control" }

func (p *pipe) LocalAddr() net.Addr                { return pipeAddr{} }
func (p *pipe) RemoteAddr() net.Addr               { return pipeAddr{} }
func (p *pipe) SetDeadline(t time.Time) error      { return nil }
func (p *pipe) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipe) SetWriteDeadline(t time.Time) error { return nil }
