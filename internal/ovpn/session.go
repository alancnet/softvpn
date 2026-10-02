package ovpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
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

	mu     sync.Mutex
	keys   [8]*keyState
	cn     string
	pi     peerInfo
	cipher string
	useEKM bool
	assign *Assignment
	pushed bool

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
	data atomic.Pointer[dataKeys]
}

func newSession(srv *Server, tr transport, remoteSID sessionID, peerID uint32) *Session {
	s := &Session{
		srv:       srv,
		tr:        tr,
		remoteSID: remoteSID,
		peerID:    peerID,
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

// CommonName is the client certificate's CN.
func (s *Session) CommonName() string { return s.cn }

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
	for _, p := range pkts {
		if err := s.tr.send(p); err != nil {
			s.Close(fmt.Sprintf("send: %v", err))
			return
		}
	}
}

// input handles one packet received from the client.
func (s *Session) input(b []byte) {
	if len(b) < 1 {
		return
	}
	switch op := opcodeOf(b[0]); op {
	case opDataV1, opDataV2:
		s.inputData(op, b)
	case opControlHardResetClientV2, opControlSoftResetV1, opControlV1, opAckV1:
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
	return s.tr.send(dk.seal(hdr, pt))
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
		fail("TLS handshake failed", err)
		return
	}
	cs := conn.ConnectionState()
	cn := cs.PeerCertificates[0].Subject.CommonName

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
	first := ks.id == 0 && s.cn == ""
	if first {
		s.cn = cn
		s.pi = parsePeerInfo(km.peerInfo)
		s.log = s.log.With("client", cn)
		s.useEKM = s.pi.protoFlags()&ivProtoTLSKeyExport != 0
		s.useV2.Store(s.pi.protoFlags()&ivProtoDataV2 != 0)
		s.cipher, _ = negotiateCipher(s.srv.opt.Ciphers, s.pi)
	}
	sameCN, cipherName, useEKM := s.cn == cn, s.cipher, s.useEKM
	s.mu.Unlock()
	if !sameCN {
		s.Close("client certificate changed during renegotiation")
		return
	}

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

	if first {
		if cipherName == "" {
			s.authFailed(conn, "no common data-channel cipher (server offers "+strings.Join(s.srv.opt.Ciphers, ":")+")")
			return
		}
		a, err := s.srv.h.Connect(s)
		if err != nil {
			s.authFailed(conn, err.Error())
			return
		}
		s.mu.Lock()
		s.assign = a
		s.mu.Unlock()
		// Hold the first keepalive back a full interval: the client cannot
		// decrypt until it has processed our key exchange message.
		s.lastDataSent.Store(time.Now().UnixNano())
		s.connected.Store(true)
	}

	dk, err := newDataKeys(cipherName, block)
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
			s.log.Info("client connected", append(attrs, "cipher", s.cipher, "key_derivation", kdf,
				"version", s.pi["IV_VER"], "platform", s.pi["IV_PLAT"])...)
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
	opts = append(opts,
		"route-gateway "+a.Gateway.String(),
		"topology subnet",
		fmt.Sprintf("ping %d", int(opt.PushPing/time.Second)),
		fmt.Sprintf("ping-restart %d", int(opt.PushPingRestart/time.Second)),
	)
	if a.IP6.IsValid() {
		opts = append(opts, "ifconfig-ipv6 "+a.IP6.String()+" "+a.Gateway6.String())
	}
	opts = append(opts, "ifconfig "+a.IP.String()+" "+a.Netmask)
	if s.useV2.Load() {
		opts = append(opts, fmt.Sprintf("peer-id %d", s.peerID))
	}
	opts = append(opts, "cipher "+s.cipher)
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
