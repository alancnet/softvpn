// Package server is the softvpn server: an OpenVPN-compatible endpoint whose
// "kernel" is entirely in userspace. It assigns virtual addresses, routes
// packets between clients, and NATs everything else out through ordinary
// host sockets.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/softvpn/softvpn/internal/ovpn"
	"github.com/softvpn/softvpn/internal/vnet"
)

// linkLocal is denied by default so clients cannot reach cloud metadata
// services (169.254.169.254) through the server.
var linkLocal = netip.MustParsePrefix("169.254.0.0/16")

// Server is the virtual router and implements ovpn.Handler.
type Server struct {
	cfg    *Config
	log    *slog.Logger
	stack  *vnet.Stack
	pinger *pinger

	mu       sync.RWMutex
	pool     *pool
	byIP     map[netip.Addr]*ovpn.Session
	byCN     map[string]*ovpn.Session
	sessions map[*ovpn.Session]netip.Addr
}

func New(cfg *Config, log *slog.Logger) (*Server, error) {
	static := map[string]netip.Addr{}
	if cfg.CCDDir != "" {
		entries, err := os.ReadDir(cfg.CCDDir)
		if err != nil {
			return nil, fmt.Errorf("client-config-dir: %w", err)
		}
		for _, e := range entries {
			cc, err := cfg.loadCCD(e.Name())
			if err != nil {
				return nil, err
			}
			if cc.IP.IsValid() {
				static[e.Name()] = cc.IP
			}
		}
	}
	return &Server{
		cfg:      cfg,
		log:      log,
		pool:     newPool(cfg.Subnet, cfg.Gateway, static),
		byIP:     map[netip.Addr]*ovpn.Session{},
		byCN:     map[string]*ovpn.Session{},
		sessions: map[*ovpn.Session]netip.Addr{},
	}, nil
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	st, err := vnet.New(s.cfg.MTU, s.deliver)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.EnableNAT(vnet.NATOptions{
		Gateway: netip.PrefixFrom(s.cfg.Gateway, s.cfg.Subnet.Bits()),
		Policy:  s.policy,
		Log:     s.log,
	}); err != nil {
		return err
	}
	s.stack = st
	s.pinger = newPinger(s.log, s.deliver)

	engine := ovpn.NewServer(ovpn.Options{
		TLS:             s.cfg.TLS,
		Ciphers:         s.cfg.Ciphers,
		PingInterval:    s.cfg.PingInterval,
		PingTimeout:     2 * s.cfg.PingTimeout, // OpenVPN doubles the server side
		PushPing:        s.cfg.PingInterval,
		PushPingRestart: s.cfg.PingTimeout,
		Wrap:            s.cfg.Wrap,
	}, s, s.log)
	if w := s.cfg.Wrap; w != nil {
		s.log.Info("control channel protected", "mode", w.Mode)
	}

	errc := make(chan error, len(s.cfg.Listeners))
	for _, l := range s.cfg.Listeners {
		switch l.Proto {
		case "udp":
			ua, err := net.ResolveUDPAddr("udp", l.Addr)
			if err != nil {
				return err
			}
			conn, err := net.ListenUDP("udp", ua)
			if err != nil {
				return err
			}
			conn.SetReadBuffer(4 << 20)
			conn.SetWriteBuffer(4 << 20)
			s.log.Info("listening", "proto", "udp", "addr", conn.LocalAddr())
			go func() { errc <- engine.ServeUDP(ctx, conn) }()
		case "tcp":
			ln, err := net.Listen("tcp", l.Addr)
			if err != nil {
				return err
			}
			s.log.Info("listening", "proto", "tcp", "addr", ln.Addr())
			go func() { errc <- engine.ServeTCP(ctx, ln) }()
		}
	}
	s.log.Info("virtual network up", "subnet", s.cfg.Subnet, "gateway", s.cfg.Gateway,
		"client_to_client", s.cfg.ClientToClient, "upstream_dns", s.cfg.UpstreamDNS, "ciphers", strings.Join(s.cfg.Ciphers, ":"))
	if s.cfg.StatusFile != "" {
		go s.statusLoop(ctx)
	}

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	s.mu.RLock()
	for ss := range s.sessions {
		go ss.Close("server shutting down")
	}
	s.mu.RUnlock()
	return err
}

// Connect implements ovpn.Handler: it authorises a client and assigns its
// address.
func (s *Server) Connect(ss *ovpn.Session) (*ovpn.Assignment, error) {
	cn := ss.CommonName()
	cc, err := s.cfg.loadCCD(cn)
	if err != nil {
		s.log.Error("client-config-dir", "client", cn, "err", err)
		return nil, errors.New("server configuration error")
	}
	if cc.Disabled {
		return nil, errors.New("client is disabled")
	}

	if !s.cfg.DuplicateCN {
		s.mu.RLock()
		old := s.byCN[cn]
		s.mu.RUnlock()
		if old != nil {
			s.log.Info("dropping previous session for same client", "client", cn, "previous", old.Remote())
			old.Close("replaced by a new connection")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxClients > 0 && len(s.sessions) >= s.cfg.MaxClients {
		return nil, errors.New("server is full")
	}
	ip, err := s.pool.alloc(cn, cc.IP, !s.cfg.DuplicateCN)
	if err != nil {
		return nil, err
	}
	s.byIP[ip] = ss
	s.sessions[ss] = ip
	if !s.cfg.DuplicateCN {
		s.byCN[cn] = ss
	}

	var push []string
	if !cc.NoPush {
		push = append(push, s.cfg.Push...)
	}
	push = append(push, cc.Push...)
	return &ovpn.Assignment{
		IP:      ip,
		Netmask: net.IP(net.CIDRMask(s.cfg.Subnet.Bits(), 32)).String(),
		Gateway: s.cfg.Gateway,
		Push:    push,
	}, nil
}

// Disconnect implements ovpn.Handler.
func (s *Server) Disconnect(ss *ovpn.Session, reason string) {
	s.mu.Lock()
	ip, ok := s.sessions[ss]
	if ok {
		delete(s.sessions, ss)
		if s.byIP[ip] == ss {
			delete(s.byIP, ip)
			s.pool.release(ip)
		}
		if s.byCN[ss.CommonName()] == ss {
			delete(s.byCN, ss.CommonName())
		}
	}
	s.mu.Unlock()
	s.log.Info("client disconnected", "client", ss.CommonName(), "ip", ip, "reason", reason,
		"rx_bytes", ss.RxBytes.Load(), "tx_bytes", ss.TxBytes.Load())
}

// Packet implements ovpn.Handler. It is the virtual router: every IP packet
// a client sends passes through here.
func (s *Server) Packet(ss *ovpn.Session, pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return // IPv4 only
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	s.mu.RLock()
	assigned := s.sessions[ss]
	s.mu.RUnlock()
	if src != assigned {
		s.log.Debug("dropping packet with spoofed source", "client", ss.CommonName(), "src", src, "assigned", assigned)
		return
	}
	switch {
	case dst == s.cfg.Gateway:
		s.stack.Inject(pkt)
	case s.cfg.Subnet.Contains(dst):
		if s.cfg.ClientToClient {
			s.deliver(pkt)
		}
	case pkt[9] == 1: // ICMP
		if _, ok := s.policy("icmp", netip.AddrPort{}, netip.AddrPortFrom(dst, 0)); ok {
			s.pinger.forward(pkt)
		}
	default:
		s.stack.Inject(pkt)
	}
}

// deliver sends a packet to the client that owns its destination address.
func (s *Server) deliver(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	s.mu.RLock()
	peer := s.byIP[dst]
	s.mu.RUnlock()
	if peer != nil {
		peer.SendPacket(pkt)
	}
}

// policy is the soft-NAT firewall. It decides whether a client flow may
// leave through the host network, and redirects DNS sent to the gateway to
// the host's resolver.
func (s *Server) policy(network string, src, dst netip.AddrPort) (string, bool) {
	a := dst.Addr()
	if a == s.cfg.Gateway {
		if dst.Port() == 53 && s.cfg.UpstreamDNS != "" {
			return s.cfg.UpstreamDNS, true
		}
		return "", false
	}
	if s.cfg.Subnet.Contains(a) || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() ||
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return "", false
	}
	for _, p := range s.cfg.NATDeny {
		if p.Contains(a) {
			return "", false
		}
	}
	if len(s.cfg.NATAllow) > 0 {
		for _, p := range s.cfg.NATAllow {
			if p.Contains(a) {
				return dst.String(), true
			}
		}
		return "", false
	}
	if linkLocal.Contains(a) {
		return "", false
	}
	return dst.String(), true
}

func (s *Server) statusLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.StatusInterval)
	defer t.Stop()
	for {
		s.writeStatus()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) writeStatus() {
	type row struct {
		ss *ovpn.Session
		ip netip.Addr
	}
	s.mu.RLock()
	rows := make([]row, 0, len(s.sessions))
	for ss, ip := range s.sessions {
		rows = append(rows, row{ss, ip})
	}
	s.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ip.Less(rows[j].ip) })

	var b strings.Builder
	fmt.Fprintf(&b, "softvpn status %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "%-24s %-15s %-28s %12s %12s\n", "COMMON NAME", "VIRTUAL IP", "REAL ADDRESS", "RX BYTES", "TX BYTES")
	for _, r := range rows {
		fmt.Fprintf(&b, "%-24s %-15s %-28s %12d %12d\n", r.ss.CommonName(), r.ip, r.ss.Remote(), r.ss.RxBytes.Load(), r.ss.TxBytes.Load())
	}
	tmp := s.cfg.StatusFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err == nil {
		os.Rename(tmp, s.cfg.StatusFile)
	} else {
		s.log.Warn("writing status file", "err", err)
	}
}
