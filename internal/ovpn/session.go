package ovpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Assignment is what the application decides for a newly authenticated
// client: its address and any extra options to push.
type Assignment struct {
	IP       netip.Addr
	Netmask  string // dotted quad, for "ifconfig"
	Gateway  netip.Addr
	IP6      netip.Prefix // address/bits for "ifconfig-ipv6"; optional
	Gateway6 netip.Addr
	Push     []string
	// TAP: the client is bridged (dev tap), so no "topology" is pushed.
	// DHCP: the client gets its address by DHCP over the bridge instead of
	// a pushed "ifconfig", and learns the gateway the same way. An invalid
	// Gateway pushes no route-gateway at all.
	TAP, DHCP bool
	// Compress is the client's compression framing ("compress"/"comp-lzo"
	// from server.conf or client-config-dir); it is pushed to the client.
	Compress Compress
}

// Handler connects sessions to the application (the virtual router).
type Handler interface {
	// Connect is called once per session after TLS and key exchange.
	Connect(s *Session) (*Assignment, error)
	// Packet delivers a decrypted IP packet from the client. The handler
	// owns the slice.
	Packet(s *Session, pkt []byte)
	// Disconnect is called once for every session Connect accepted.
	Disconnect(s *Session, reason string)
}

// Credentials are what a client presented in one key exchange.
type Credentials struct {
	Certificate   *x509.Certificate // nil if the client sent none
	Username      string            // from auth-user-pass; empty if not sent
	Password      string
	Renegotiation bool // false for the session's first key exchange
}

// Authenticator is an optional Handler extension that checks credentials.
// Authenticate is called for every key exchange, the first (before Connect)
// and each renegotiation, and returns the common name the session is known
// by. An error is sent to the client as AUTH_FAILED and ends the session.
// Handlers without it accept any client whose certificate passed TLS
// verification, under the certificate's CN.
type Authenticator interface {
	Authenticate(s *Session, c *Credentials) (commonName string, err error)
}

// transport sends wire packets to one client.
type transport interface {
	send(pkt []byte) error
	remote() string
	reliable() bool // true for TCP: no control-channel retransmission needed
	close()
}

// Session is one client: its control channel, key states and data channel.
type Session struct {
	srv *Server
	tr  transport
	log *slog.Logger

	localSID  sessionID
	remoteSID sessionID
	peerID    uint32
	created   time.Time
	wrap      *tlsWrap   // tls-auth / tls-crypt state; nil without
	sendMu    sync.Mutex // keeps wrapped control packets in packet-id order

	mu     sync.Mutex
	keys   [8]*keyState
	cn     string
	user   string
	cert   *x509.Certificate
	pi     peerInfo
	cipher string
	useEKM bool
	assign *Assignment
	pushed bool

	pushCipher bool       // negotiated with a client that takes a pushed cipher
	clientComp bool       // client announced compression (OCC "comp-lzo")
	comp       compressor // set before the first data key is published
	compPush   string

	primary      atomic.Pointer[keyState] // key used to send data
	useV2        atomic.Bool
	lastRecv     atomic.Int64
	lastDataSent atomic.Int64
	RxBytes      atomic.Uint64
	TxBytes      atomic.Uint64

	connected atomic.Bool
	done      chan struct{}
	closeOnce sync.Once
}

type keyState struct {
	id   byte
	rel  *reliable
	pipe *pipe
	conn atomic.Pointer[tls.Conn] // once the handshake is done
	data atomic.Pointer[dataKeys]
}

func newSession(srv *Server, tr transport, remoteSID sessionID, peerID uint32, wrap *tlsWrap) *Session {
	s := &Session{
		srv:       srv,
		tr:        tr,
		remoteSID: remoteSID,
		peerID:    peerID,
		wrap:      wrap,
		created:   time.Now(),
		done:      make(chan struct{}),
	}
	copy(s.localSID[:], randomBytes(8))
	s.log = srv.log.With("remote", tr.remote())
	s.lastRecv.Store(time.Now().UnixNano())
	s.newKeyState(0, opControlHardResetServerV2)
	go s.timers()
	return s
}

// CommonName is the client certificate's CN, or what the Authenticator
// chose (the username, with username-as-common-name).
func (s *Session) CommonName() string { return s.cn }

// Username is the auth-user-pass username the session authenticated with,
// or "" for certificate-only clients.
func (s *Session) Username() string { return s.user }

// Certificate is the client certificate from the latest key exchange, or
// nil if the client did not send one.
func (s *Session) Certificate() *x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cert
}

// PeerInfo returns an IV_* value the client sent (e.g. "IV_VER").
func (s *Session) PeerInfo(key string) string { return s.pi[key] }

// Remote is the client's transport address.
func (s *Session) Remote() string { return s.tr.remote() }

// Close ends the session.
func (s *Session) Close(reason string) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		for _, ks := range s.keys {
			if ks != nil {
				ks.pipe.Close()
			}
		}
		s.mu.Unlock()
		close(s.done)
		s.tr.close()
		s.srv.forget(s)
		if s.connected.Load() {
			s.srv.h.Disconnect(s, reason)
		} else {
			s.log.Info("handshake abandoned", "reason", reason)
		}
	})
}

// Kick tells the client why it is being disconnected, then ends the
// session. msg is an OpenVPN control message: "AUTH_FAILED,reason" makes a
// stock client stop; "RESTART" makes it reconnect.
func (s *Session) Kick(msg, reason string) {
	if ks := s.primary.Load(); ks != nil {
		if conn := ks.conn.Load(); conn != nil {
			conn.Write([]byte(msg + "\x00"))
		}
	}
	time.AfterFunc(2*time.Second, func() { s.Close(reason) })
}

// newKeyState must be called with s.mu held (or before the session is shared).
func (s *Session) newKeyState(id byte, initialOp byte) *keyState {
	ks := &keyState{id: id, rel: newReliable(id, !s.tr.reliable())}
	ks.rel.enqueue(initialOp, nil)
	ks.pipe = newPipe(func(b []byte) {
		s.mu.Lock()
		ks.rel.enqueue(opControlV1, b)
		out := ks.rel.collect(time.Now(), s.localSID, s.remoteSID)
		s.mu.Unlock()
		s.sendAll(out)
	})
	s.keys[id] = ks
	go s.runKey(ks)
	return ks
}

func (s *Session) sendAll(pkts [][]byte) {
	var err error
	s.sendMu.Lock()
	for _, p := range pkts {
		if s.wrap != nil {
			p = s.wrap.wrap(p)
		}
		if err = s.tr.send(p); err != nil {
			break
		}
	}
	s.sendMu.Unlock()
	if err != nil {
		s.Close(fmt.Sprintf("send: %v", err))
	}
}

// input handles one packet received from the client.
func (s *Session) input(b []byte) {
	if len(b) < 1 {
		return
	}
	switch op := opcodeOf(b[0]); {
	case op == opDataV1 || op == opDataV2:
		s.inputData(op, b)
	case isControl(op):
		if s.wrap != nil {
			var err error
			if b, err = s.wrap.unwrapInput(b); err != nil {
				s.log.Debug("dropping control packet", "mode", s.wrap.mode, "err", err)
				return
			}
		} else if hasWKc(op) {
			s.log.Debug("ignoring tls-crypt-v2 packet: server has no tls-crypt-v2 key", "opcode", op)
			return
		}
		s.inputControl(b)
	default:
		s.log.Debug("ignoring packet with unsupported opcode", "opcode", op)
	}
}

func (s *Session) inputControl(b []byte) {
	p, err := parseControl(b)
	if err != nil {
		s.log.Debug("bad control packet", "err", err)
		return
	}
	if p.sid != s.remoteSID || len(p.acks) > 0 && p.ackedSID != s.localSID {
		s.log.Debug("control packet for another session")
		return
	}
	s.lastRecv.Store(time.Now().UnixNano())
	s.mu.Lock()
	ks := s.keys[p.keyID]
	if ks == nil {
		if p.op != opControlSoftResetV1 || p.keyID == 0 {
			s.mu.Unlock()
			return
		}
		// Client-initiated renegotiation (reneg-sec): a fresh key state with
		// its own reliability sequence and TLS session.
		s.log.Debug("renegotiation started", "key_id", p.keyID)
		ks = s.newKeyState(p.keyID, opControlSoftResetV1)
	}
	ks.rel.ack(p.acks)
	if p.op != opAckV1 {
		for _, m := range ks.rel.receive(p.messageID, p.op, p.payload) {
			if m.op == opControlV1 {
				ks.pipe.feed(m.payload)
			}
		}
	}
	out := ks.rel.collect(time.Now(), s.localSID, s.remoteSID)
	s.mu.Unlock()
	s.sendAll(out)
}

// inputData decrypts a data packet. It reports whether the packet was
// authentic, which the UDP transport uses to allow client address changes.
func (s *Session) inputData(op byte, b []byte) bool {
	s.mu.Lock()
	ks := s.keys[keyIDOf(b[0])]
	s.mu.Unlock()
	if ks == nil {
		return false
	}
	dk := ks.data.Load()
	if dk == nil {
		return false
	}
	hdr := 1
	if op == opDataV2 {
		hdr = 4
	}
	pt, err := dk.open(b, hdr)
	if err != nil {
		s.log.Debug("dropping data packet", "err", err)
		return false
	}
	s.lastRecv.Store(time.Now().UnixNano())
	if pt, err = s.comp.unframe(pt); err != nil {
		s.log.Debug("dropping data packet", "err", err)
		return true
	}
	switch {
	case bytes.Equal(pt, pingMagic):
	case len(pt) > len(occMagic) && bytes.HasPrefix(pt, occMagic):
		if pt[len(occMagic)] == occExit {
			go s.Close("client exited")
		}
	case len(pt) > 0 && s.connected.Load():
		s.RxBytes.Add(uint64(len(pt)))
		s.srv.h.Packet(s, pt)
	}
	return true
}

// SendPacket encrypts an IP packet and sends it to the client.
func (s *Session) SendPacket(pkt []byte) {
	if err := s.sendData(pkt); err == nil {
		s.TxBytes.Add(uint64(len(pkt)))
	}
}

func (s *Session) sendData(pt []byte) error {
	ks := s.primary.Load()
	if ks == nil {
		return errors.New("no data channel key")
	}
	dk := ks.data.Load()
	var hdr []byte
	if s.useV2.Load() {
		hdr = []byte{opDataV2<<3 | ks.id, byte(s.peerID >> 16), byte(s.peerID >> 8), byte(s.peerID)}
	} else {
		hdr = []byte{opDataV1<<3 | ks.id}
	}
	s.lastDataSent.Store(time.Now().UnixNano())
	return s.tr.send(dk.seal(hdr, s.comp.frame(pt)))
}

// runKey drives one key state: TLS handshake, key exchange, then control
// messages (PUSH_REQUEST, EXIT) arriving over TLS.
func (s *Session) runKey(ks *keyState) {
	conn := tls.Server(ks.pipe, s.srv.opt.TLS)
	ctx, cancel := context.WithTimeout(context.Background(), s.srv.opt.HandshakeWindow)
	defer cancel()
	fail := func(msg string, err error) {
		if ks.id == 0 {
			s.Close(fmt.Sprintf("%s: %v", msg, err))
		} else {
			s.log.Warn("renegotiation failed", "key_id", ks.id, "step", msg, "err", err)
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		if ks.id != 0 && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			// e.g. the certificate has been revoked since the session began
			s.Close(fmt.Sprintf("renegotiation TLS handshake failed: %v", err))
			return
		}
		fail("TLS handshake failed", err)
		return
	}
	ks.conn.Store(conn)
	cs := conn.ConnectionState()
	var cert *x509.Certificate
	if len(cs.PeerCertificates) > 0 {
		cert = cs.PeerCertificates[0]
	}

	// Key method 2: OpenVPN writes it in one TLS record, so it normally
	// arrives in a single read.
	var buf []byte
	var km *clientKeyMethod2
	chunk := make([]byte, 16<<10)
	for {
		n, err := conn.Read(chunk)
		if err != nil {
			fail("reading key exchange", err)
			return
		}
		buf = append(buf, chunk[:n]...)
		if km, err = parseClientKeyMethod2(buf); err == nil {
			break
		} else if !errors.Is(err, errIncomplete) {
			fail("bad key exchange", err)
			return
		}
	}

	s.mu.Lock()
	first := ks.id == 0
	if first {
		s.pi = parsePeerInfo(km.peerInfo)
		s.log.Debug("key exchange", "options", km.options, "peer_info", strings.ReplaceAll(km.peerInfo, "\n", " "))
		s.useEKM = s.pi.protoFlags()&ivProtoTLSKeyExport != 0
		s.useV2.Store(s.pi.protoFlags()&ivProtoDataV2 != 0)
		occCipher, _ := occOption(km.options, "cipher")
		s.cipher, s.pushCipher = negotiateCipher(s.srv.opt.Ciphers, s.pi, occCipher, s.srv.opt.CipherFallback)
		_, s.clientComp = occOption(km.options, "comp-lzo")
		if auth, _ := occOption(km.options, "auth"); isCBC(s.cipher) && auth != "" && !strings.EqualFold(auth, s.srv.opt.Digest) {
			s.log.Warn("client uses a different auth digest; its data packets will fail authentication",
				"client_auth", auth, "server_auth", s.srv.opt.Digest)
		}
	}
	cipherName, useEKM := s.cipher, s.useEKM
	s.mu.Unlock()

	sRand1, sRand2 := randomBytes(32), randomBytes(32)
	var block []byte
	if useEKM {
		var err error
		if block, err = cs.ExportKeyingMaterial(ekmLabel, nil, keyBlockSize); err != nil {
			fail("exporting keying material", err)
			return
		}
	} else {
		block = openvpnPRFKeys(km.preMaster, km.random1, sRand1, km.random2, sRand2, s.remoteSID, s.localSID)
	}
	options := strings.Replace(km.options, "tls-client", "tls-server", 1)
	if _, err := conn.Write(serverKeyMethod2(sRand1, sRand2, options)); err != nil {
		fail("sending key exchange", err)
		return
	}

	if first && cipherName == "" {
		s.authFailed(conn, "no common data-channel cipher (server offers "+strings.Join(s.srv.opt.Ciphers, ":")+")")
		return
	}
	cn, err := s.authenticate(&Credentials{Certificate: cert, Username: km.username, Password: km.password, Renegotiation: !first})
	if err != nil {
		s.authFailed(conn, err.Error())
		return
	}
	s.mu.Lock()
	sameCN := first || s.cn == cn
	if first {
		s.cn, s.user = cn, km.username
		s.log = s.log.With("client", cn)
	}
	if sameCN {
		s.cert = cert
	}
	s.mu.Unlock()
	if !sameCN {
		s.Close("client identity changed during renegotiation")
		return
	}

	if first {
		a, err := s.srv.h.Connect(s)
		if err != nil {
			s.authFailed(conn, err.Error())
			return
		}
		s.mu.Lock()
		s.assign = a
		s.mu.Unlock()
		s.setCompression(a)
		// Hold the first keepalive back a full interval: the client cannot
		// decrypt until it has processed our key exchange message.
		s.lastDataSent.Store(time.Now().UnixNano())
		s.connected.Store(true)
	}

	dk, err := newDataKeys(cipherName, s.srv.opt.Digest, block)
	if err != nil {
		fail("data channel keys", err)
		return
	}
	ks.data.Store(dk)
	if old := s.primary.Swap(ks); old != nil && old != ks {
		go s.retire(old)
	}
	if ks.id == 0 {
		s.log.Debug("data channel keys established", "key_id", ks.id, "cipher", cipherName, "ekm", useEKM)
	} else {
		s.log.Info("data channel rekeyed", "key_id", ks.id)
	}

	s.readControlMessages(conn)
}

// authenticate checks a key exchange's credentials with the handler.
func (s *Session) authenticate(c *Credentials) (string, error) {
	if a, ok := s.srv.h.(Authenticator); ok {
		return a.Authenticate(s, c)
	}
	if c.Certificate == nil {
		return "", errors.New("client certificate required")
	}
	return c.Certificate.Subject.CommonName, nil
}

// retire drops a superseded key after OpenVPN's default transition window,
// during which in-flight packets under the old key are still accepted.
func (s *Session) retire(old *keyState) {
	select {
	case <-time.After(60 * time.Second):
	case <-s.done:
		return
	}
	s.mu.Lock()
	if s.keys[old.id] == old {
		s.keys[old.id] = nil
		old.pipe.Close()
	}
	s.mu.Unlock()
}

func (s *Session) authFailed(conn *tls.Conn, reason string) {
	s.log.Warn("client rejected", "reason", reason)
	conn.Write([]byte("AUTH_FAILED," + reason + "\x00"))
	time.AfterFunc(2*time.Second, func() { s.Close("auth failed: " + reason) })
}

func (s *Session) readControlMessages(conn *tls.Conn) {
	var pending []byte
	buf := make([]byte, 16<<10)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		pending = append(pending, buf[:n]...)
		for {
			i := bytes.IndexByte(pending, 0)
			if i < 0 {
				break
			}
			msg := string(pending[:i])
			pending = pending[i+1:]
			s.controlMessage(conn, msg)
		}
	}
}

func (s *Session) controlMessage(conn *tls.Conn, msg string) {
	switch {
	case msg == "PUSH_REQUEST":
		s.mu.Lock()
		a, first := s.assign, !s.pushed
		s.pushed = true
		s.mu.Unlock()
		if a == nil {
			return
		}
		for _, m := range s.pushReply(a) {
			conn.Write([]byte(m + "\x00"))
		}
		if first {
			kdf := "openvpn-prf"
			if s.useEKM {
				kdf = "tls-ekm"
			}
			attrs := []any{"ip", a.IP}
			if a.IP6.IsValid() {
				attrs = append(attrs, "ip6", a.IP6.Addr())
			}
			attrs = append(attrs, "cipher", s.cipher, "key_derivation", kdf,
				"version", s.pi["IV_VER"], "platform", s.pi["IV_PLAT"])
			if isCBC(s.cipher) {
				attrs = append(attrs, "auth", s.srv.opt.Digest)
			}
			if s.comp.mode != CompressUnset {
				attrs = append(attrs, "compress", s.comp.mode)
			}
			s.log.Info("client connected", attrs...)
		}
	case msg == "EXIT" || strings.HasPrefix(msg, "EXIT,"):
		go s.Close("client exited")
	default:
		s.log.Debug("ignoring control message", "msg", msg)
	}
}

// pushReply builds PUSH_REPLY messages, splitting long option lists with
// push-continuation like OpenVPN does.
func (s *Session) pushReply(a *Assignment) []string {
	opt := s.srv.opt
	opts := append([]string(nil), a.Push...)
	switch {
	case !a.Gateway.IsValid():
	case a.DHCP:
		opts = append(opts, "route-gateway dhcp")
	default:
		opts = append(opts, "route-gateway "+a.Gateway.String())
	}
	if !a.TAP {
		opts = append(opts, "topology subnet")
	}
	opts = append(opts,
		fmt.Sprintf("ping %d", int(opt.PushPing/time.Second)),
		fmt.Sprintf("ping-restart %d", int(opt.PushPingRestart/time.Second)),
	)
	if a.IP6.IsValid() {
		opts = append(opts, "ifconfig-ipv6 "+a.IP6.String()+" "+a.Gateway6.String())
	}
	if !a.DHCP {
		opts = append(opts, "ifconfig "+a.IP.String()+" "+a.Netmask)
	}
	if s.useV2.Load() {
		opts = append(opts, fmt.Sprintf("peer-id %d", s.peerID))
	}
	if s.pushCipher {
		opts = append(opts, "cipher "+s.cipher)
	}
	if s.compPush != "" {
		opts = append(opts, s.compPush)
	}
	var flags []string
	if s.pi.protoFlags()&ivProtoCCExitNotify != 0 {
		flags = append(flags, "cc-exit")
	}
	if s.useEKM {
		opts = append(opts, "key-derivation tls-ekm")
		flags = append(flags, "tls-ekm")
	}
	if len(flags) > 0 {
		opts = append(opts, "protocol-flags "+strings.Join(flags, " "))
	}

	const limit = 1000
	var msgs []string
	cur := "PUSH_REPLY"
	for _, o := range opts {
		if len(cur)+1+len(o) > limit-len(",push-continuation 2") {
			msgs = append(msgs, cur+",push-continuation 2")
			cur = "PUSH_REPLY"
		}
		cur += "," + o
	}
	if len(msgs) > 0 {
		cur += ",push-continuation 1"
	}
	return append(msgs, cur)
}

// timers handles retransmission, keepalive pings and timeouts.
func (s *Session) timers() {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			var out [][]byte
			for _, ks := range s.keys {
				if ks != nil {
					out = append(out, ks.rel.collect(now, s.localSID, s.remoteSID)...)
				}
			}
			s.mu.Unlock()
			s.sendAll(out)

			opt := s.srv.opt
			if !s.connected.Load() && now.Sub(s.created) > opt.HandshakeWindow {
				s.Close("handshake timeout")
				return
			}
			if now.Sub(time.Unix(0, s.lastRecv.Load())) > opt.PingTimeout {
				s.Close("ping timeout")
				return
			}
			if s.connected.Load() && now.Sub(time.Unix(0, s.lastDataSent.Load())) > opt.PingInterval {
				s.sendData(pingMagic)
			}
		}
	}
}
