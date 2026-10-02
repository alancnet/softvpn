package ovpn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Options configures the protocol engine.
type Options struct {
	TLS             *tls.Config
	Ciphers         []string      // data-ciphers, in preference order
	PingInterval    time.Duration // server sends a keepalive after this much idle
	PingTimeout     time.Duration // server drops a client silent this long
	PushPing        time.Duration // pushed "ping"
	PushPingRestart time.Duration // pushed "ping-restart"
	HandshakeWindow time.Duration
}

// Server accepts OpenVPN clients over UDP and/or TCP.
type Server struct {
	opt Options
	h   Handler
	log *slog.Logger

	mu       sync.Mutex
	byPeerID map[uint32]*Session
	byAddr   map[netip.AddrPort]*Session // UDP sessions
	nextPeer uint32
}

func NewServer(opt Options, h Handler, log *slog.Logger) *Server {
	if len(opt.Ciphers) == 0 {
		opt.Ciphers = SupportedCiphers
	}
	if opt.HandshakeWindow == 0 {
		opt.HandshakeWindow = 60 * time.Second
	}
	return &Server{opt: opt, h: h, log: log, byPeerID: map[uint32]*Session{}, byAddr: map[netip.AddrPort]*Session{}}
}

func (srv *Server) register(tr transport, sid sessionID, addr netip.AddrPort) *Session {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	// Peer ids are 24 bits; 0xFFFFFF is reserved ("undefined").
	for {
		srv.nextPeer = (srv.nextPeer + 1) % 0xFFFFFF
		if _, used := srv.byPeerID[srv.nextPeer]; !used {
			break
		}
	}
	s := newSession(srv, tr, sid, srv.nextPeer)
	srv.byPeerID[s.peerID] = s
	if addr.IsValid() {
		srv.byAddr[addr] = s
	}
	return s
}

func (srv *Server) forget(s *Session) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.byPeerID[s.peerID] == s {
		delete(srv.byPeerID, s.peerID)
	}
	if u, ok := s.tr.(*udpTransport); ok {
		if a := u.addr(); srv.byAddr[a] == s {
			delete(srv.byAddr, a)
		}
	}
}

func isHardReset(b []byte) bool { return len(b) > 0 && opcodeOf(b[0]) == opControlHardResetClientV2 }

// ---- UDP ----

type udpTransport struct {
	conn *net.UDPConn
	mu   sync.Mutex
	peer netip.AddrPort
}

func (u *udpTransport) addr() netip.AddrPort {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.peer
}

func (u *udpTransport) send(p []byte) error {
	_, err := u.conn.WriteToUDPAddrPort(p, u.addr())
	return err
}
func (u *udpTransport) remote() string { return "udp:" + u.addr().String() }
func (u *udpTransport) reliable() bool { return false }
func (u *udpTransport) close()         {}

// ServeUDP serves clients on a UDP socket until ctx is cancelled.
func (srv *Server) ServeUDP(ctx context.Context, conn *net.UDPConn) error {
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	buf := make([]byte, 65536)
	for {
		n, addr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		pkt := append([]byte(nil), buf[:n]...)
		srv.inputUDP(conn, addr, pkt)
	}
}

func (srv *Server) inputUDP(conn *net.UDPConn, addr netip.AddrPort, pkt []byte) {
	srv.mu.Lock()
	s := srv.byAddr[addr]
	srv.mu.Unlock()

	if isHardReset(pkt) {
		p, err := parseControl(pkt)
		if err != nil {
			return
		}
		if s != nil && s.remoteSID == p.sid {
			s.input(pkt) // retransmitted reset
			return
		}
		if s != nil {
			s.Close("client restarted")
		}
		s = srv.register(&udpTransport{conn: conn, peer: addr}, p.sid, addr)
		s.log.Debug("new session")
		s.input(pkt)
		return
	}

	if s != nil {
		s.input(pkt)
		return
	}
	// Unknown address: a P_DATA_V2 packet names its session by peer id, so a
	// client whose address changed (NAT rebinding, roaming) can "float" once
	// a packet from the new address authenticates.
	if len(pkt) >= 4 && opcodeOf(pkt[0]) == opDataV2 {
		id := uint32(pkt[1])<<16 | uint32(pkt[2])<<8 | uint32(pkt[3])
		srv.mu.Lock()
		s = srv.byPeerID[id]
		srv.mu.Unlock()
		if s == nil {
			return
		}
		u, ok := s.tr.(*udpTransport)
		if !ok || !s.inputData(opDataV2, pkt) {
			return
		}
		srv.mu.Lock()
		u.mu.Lock()
		old := u.peer
		u.peer = addr
		u.mu.Unlock()
		if srv.byAddr[old] == s {
			delete(srv.byAddr, old)
		}
		srv.byAddr[addr] = s
		srv.mu.Unlock()
		s.log.Info("client floated to new address", "from", old, "to", addr)
	}
}

// ---- TCP ----

type tcpTransport struct {
	conn net.Conn
	mu   sync.Mutex
}

func (t *tcpTransport) send(p []byte) error {
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := t.conn.Write(b)
	return err
}
func (t *tcpTransport) remote() string { return "tcp:" + t.conn.RemoteAddr().String() }
func (t *tcpTransport) reliable() bool { return true }
func (t *tcpTransport) close()         { t.conn.Close() }

// ServeTCP serves clients on a TCP listener until ctx is cancelled.
func (srv *Server) ServeTCP(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go srv.serveTCPConn(ctx, c)
	}
}

func (srv *Server) serveTCPConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	var hdr [2]byte
	buf := make([]byte, 65535)
	read := func() ([]byte, error) {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c, buf[:n]); err != nil {
			return nil, err
		}
		return append([]byte(nil), buf[:n]...), nil
	}

	c.SetReadDeadline(time.Now().Add(srv.opt.HandshakeWindow))
	first, err := read()
	if err != nil || !isHardReset(first) {
		srv.log.Debug("tcp: expected hard reset", "remote", c.RemoteAddr(), "err", err)
		return
	}
	p, err := parseControl(first)
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	s := srv.register(&tcpTransport{conn: c}, p.sid, netip.AddrPort{})
	s.log.Debug("new session")
	s.input(first)
	for {
		pkt, err := read()
		if err != nil {
			reason := "connection closed by client"
			if !errors.Is(err, io.EOF) {
				reason = "read: " + err.Error()
			}
			s.Close(reason)
			return
		}
		s.input(pkt)
	}
}
