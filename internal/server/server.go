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
	bridge *bridge // TAP mode only

	mu       sync.RWMutex
	pool     *pool
	routes   *routes
	byCN     map[string]*ovpn.Session
	sessions map[*ovpn.Session]*peer
	tokens   map[*ovpn.Session]string // auth-token to push at Connect
}

// peer is the router's view of a connected client: its addresses and the
// networks behind it.
type peer struct {
	ip      netip.Addr
	ip6     netip.Addr // invalid without server-ipv6
	iroutes []netip.Prefix
}

// prefixes is every route that points at the client.
func (p *peer) prefixes() []netip.Prefix {
	ps := append([]netip.Prefix{netip.PrefixFrom(p.ip, 32)}, p.iroutes...)
	if p.ip6.IsValid() {
		ps = append(ps, netip.PrefixFrom(p.ip6, 128))
	}
	return ps
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
	s := &Server{
		cfg:      cfg,
		log:      log,
		pool:     newPool(cfg.Subnet, cfg.Gateway, static),
		routes:   newRoutes(),
		byCN:     map[string]*ovpn.Session{},
		sessions: map[*ovpn.Session]*peer{},
		tokens:   map[*ovpn.Session]string{},
	}
	if cfg.PoolStart.IsValid() {
		s.pool.first, s.pool.last = cfg.PoolStart, cfg.PoolEnd
	}
	if cfg.TAP {
		s.bridge = s.newBridge()
	}
	return s, nil
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	st, err := vnet.New(s.cfg.MTU, s.deliver)
	if err != nil {
		return err
	}
	defer st.Close()
	nat := vnet.NATOptions{
		Gateway: netip.PrefixFrom(s.cfg.Gateway, s.cfg.Subnet.Bits()),
		Policy:  s.policy,
		Log:     s.log,
	}
	if s.cfg.Subnet6.IsValid() {
		nat.Gateway6 = netip.PrefixFrom(s.cfg.Gateway6, s.cfg.Subnet6.Bits())
	}
	if err := st.EnableNAT(nat); err != nil {
		return err
	}
	s.stack = st
	s.pinger = newPinger(s.log, s.deliver)

	tlsConf := s.cfg.TLS
	if s.cfg.Auth.CRL != nil {
		tlsConf = tlsConf.Clone()
		tlsConf.VerifyConnection = s.verifyConnection
	}
	engine := ovpn.NewServer(ovpn.Options{
		TLS:             tlsConf,
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
			ua, err := net.ResolveUDPAddr(l.Network, l.Addr)
			if err != nil {
				return err
			}
			conn, err := net.ListenUDP(l.Network, ua)
			if err != nil {
				return err
			}
			conn.SetReadBuffer(4 << 20)
			conn.SetWriteBuffer(4 << 20)
			s.log.Info("listening", "proto", l.Network, "addr", conn.LocalAddr())
			go func() { errc <- engine.ServeUDP(ctx, conn) }()
		case "tcp":
			ln, err := net.Listen(l.Network, l.Addr)
			if err != nil {
				return err
			}
			s.log.Info("listening", "proto", l.Network, "addr", ln.Addr())
			go func() { errc <- engine.ServeTCP(ctx, ln) }()
		}
	}
	attrs := []any{"subnet", s.cfg.Subnet, "gateway", s.cfg.Gateway}
	if s.cfg.Subnet6.IsValid() {
		attrs = append(attrs, "subnet6", s.cfg.Subnet6, "gateway6", s.cfg.Gateway6)
	}
	if len(s.cfg.Routes) > 0 {
		attrs = append(attrs, "routes", s.cfg.Routes)
	}
	s.log.Info("virtual network up", append(attrs,
		"client_to_client", s.cfg.ClientToClient, "upstream_dns", s.cfg.UpstreamDNS, "ciphers", strings.Join(s.cfg.Ciphers, ":"))...)
	if s.bridge != nil {
		s.log.Info("virtual switch up (dev tap)", "gateway_mac", s.cfg.MAC.String(), "pool", s.pool.first.String()+"-"+s.pool.last.String(), "dhcp_only", s.cfg.DHCP)
	}
	if s.cfg.StatusFile != "" {
		go s.statusLoop(ctx)
	}
	if s.cfg.Auth.CRL != nil || s.cfg.Auth.Users != nil {
		s.log.Info("client authentication", "verify_client_cert", s.cfg.Auth.VerifyClientCert,
			"users", s.cfg.Auth.Users != nil, "crl", s.cfg.Auth.CRL != nil, "auth_gen_token", s.cfg.Auth.AuthGenToken)
		go s.authWatch(ctx)
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
	token := s.takeToken(ss)
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
	ip6 := cc.IP6
	if !ip6.IsValid() {
		ip6 = s.cfg.ipv6For(ip)
	}
	if ip6.IsValid() {
		if other := s.routes.hosts[ip6.Addr()]; other != nil && other != ss {
			s.pool.release(ip)
			return nil, fmt.Errorf("address %s is already in use", ip6.Addr())
		}
	}
	p := &peer{ip: ip, ip6: ip6.Addr(), iroutes: cc.IRoutes}
	for _, r := range p.prefixes() {
		if prev := s.routes.add(r, ss); prev != nil && prev != ss {
			s.log.Warn("iroute moved to another client", "route", r, "from", prev.CommonName(), "to", cn)
		}
	}
	s.sessions[ss] = p
	if !s.cfg.DuplicateCN {
		s.byCN[cn] = ss
	}

	var push []string
	if !cc.NoPush {
		push = append(push, s.cfg.Push...)
	}
	push = append(push, cc.Push...)
	if token != "" {
		push = append(push, "auth-token "+token)
	}
	a := &ovpn.Assignment{
		IP:       ip,
		Netmask:  net.IP(net.CIDRMask(s.cfg.Subnet.Bits(), 32)).String(),
		Gateway:  s.cfg.Gateway,
		IP6:      ip6,
		Gateway6: s.cfg.Gateway6,
		Push:     withoutOwnRoutes(push, cc.IRoutes),
	}
	if s.bridge != nil {
		s.bridge.attach(ss, ip, push)
		a.TAP, a.DHCP = true, s.cfg.DHCP
		if s.cfg.NoGateway {
			a.Gateway = netip.Addr{}
		}
	}
	return a, nil
}

// withoutOwnRoutes drops pushed "route"/"route-ipv6" options for networks
// that are behind the client itself (its iroutes), as OpenVPN does: they
// would point the client's own LAN back into the tunnel.
func withoutOwnRoutes(push []string, iroutes []netip.Prefix) []string {
	if len(iroutes) == 0 {
		return push
	}
	var out []string
	for _, o := range push {
		if r, ok := pushedRoute(o); ok && covers(iroutes, r) {
			continue
		}
		out = append(out, o)
	}
	return out
}

// pushedRoute parses a pushed "route NETWORK [NETMASK ...]" or "route-ipv6
// PREFIX ..." option.
func pushedRoute(opt string) (netip.Prefix, bool) {
	f := strings.Fields(opt)
	var r netip.Prefix
	var err error
	switch {
	case len(f) == 2 && f[0] == "route":
		r, err = parseRoute4(f[1], "")
	case len(f) > 2 && f[0] == "route":
		r, err = parseRoute4(f[1], f[2])
	case len(f) >= 2 && f[0] == "route-ipv6":
		r, err = parseRoute6(f[1])
	default:
		return r, false
	}
	return r, err == nil
}

// covers reports whether r lies entirely within one of nets.
func covers(nets []netip.Prefix, r netip.Prefix) bool {
	for _, n := range nets {
		if n.Bits() <= r.Bits() && n.Contains(r.Addr()) {
			return true
		}
	}
	return false
}

// Disconnect implements ovpn.Handler.
func (s *Server) Disconnect(ss *ovpn.Session, reason string) {
	s.mu.Lock()
	p, ok := s.sessions[ss]
	var ip netip.Addr
	if ok {
		ip = p.ip
		delete(s.sessions, ss)
		if s.routes.hosts[ip] == ss {
			s.pool.release(ip)
		}
		for _, r := range p.prefixes() {
			s.routes.remove(r, ss)
		}
		if s.byCN[ss.CommonName()] == ss {
			delete(s.byCN, ss.CommonName())
		}
	}
	s.mu.Unlock()
	if s.bridge != nil {
		s.bridge.detach(ss)
	}
	s.log.Info("client disconnected", "client", ss.CommonName(), "ip", ip, "reason", reason,
		"rx_bytes", ss.RxBytes.Load(), "tx_bytes", ss.TxBytes.Load())
}

// Packet implements ovpn.Handler. It is the virtual router: every IP packet
// a client sends passes through here.
func (s *Server) Packet(ss *ovpn.Session, pkt []byte) {
	if s.bridge != nil {
		s.bridge.input(ss, pkt) // an Ethernet frame
		return
	}
	h, ok := parseIP(pkt)
	if !ok || h.dst.IsMulticast() {
		return // includes IPv6 router solicitations and MLD from the tun
	}
	s.mu.RLock()
	from, to := s.routes.lookup(h.src), s.routes.lookup(h.dst)
	s.mu.RUnlock()
	// Source validation: the client's own addresses or a network behind it.
	if from != ss {
		if !h.src.IsLinkLocalUnicast() {
			s.log.Debug("dropping packet with spoofed source", "client", ss.CommonName(), "src", h.src)
		}
		return
	}
	switch {
	case h.dst == s.cfg.Gateway || h.dst == s.cfg.Gateway6 && h.dst.IsValid():
		s.stack.Inject(pkt)
	case to != nil && to != ss: // another client, or a network behind one
		if s.cfg.ClientToClient {
			to.SendPacket(pkt)
		}
	case s.cfg.internal(h.dst):
		// Inside the VPN but nobody serves it (yet): unreachable.
	case h.dst.Is4() && h.proto == protoICMP || h.isEcho6(pkt):
		// Other ICMPv6 (e.g. packet too big for a NATed flow) goes to the
		// stack below.
		if _, ok := s.policy("icmp", netip.AddrPort{}, netip.AddrPortFrom(h.dst, 0)); ok {
			s.pinger.forward(h, pkt)
		}
	default:
		s.stack.Inject(pkt)
	}
}

// deliver sends a packet to the client that owns its destination address
// (or the network behind a client that it belongs to).
func (s *Server) deliver(pkt []byte) {
	if s.bridge != nil {
		s.bridge.output(pkt)
		return
	}
	h, ok := parseIP(pkt)
	if !ok {
		return
	}
	s.mu.RLock()
	peer := s.routes.lookup(h.dst)
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
	if a == s.cfg.Gateway || a == s.cfg.Gateway6 && a.IsValid() {
		if dst.Port() == 53 && s.cfg.UpstreamDNS != "" {
			return s.cfg.UpstreamDNS, true
		}
		return "", false
	}
	// IPv4-mapped IPv6 addresses would let a client reach IPv4 (including
	// the host's loopback) under an IPv6 name, so they are refused outright.
	if s.cfg.internal(a) || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() ||
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
	if linkLocal.Contains(a) || a.Is6() && a.IsLinkLocalUnicast() {
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
		p  peer
	}
	s.mu.RLock()
	rows := make([]row, 0, len(s.sessions))
	for ss, p := range s.sessions {
		rows = append(rows, row{ss, *p})
	}
	s.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].p.ip.Less(rows[j].p.ip) })

	var b strings.Builder
	fmt.Fprintf(&b, "softvpn status %s\n", time.Now().UTC().Format(time.RFC3339))
	v6 := s.cfg.Subnet6.IsValid()
	fmt.Fprintf(&b, "%-24s %-15s %-28s %12s %12s", "COMMON NAME", "VIRTUAL IP", "REAL ADDRESS", "RX BYTES", "TX BYTES")
	if v6 {
		fmt.Fprintf(&b, " %s", "VIRTUAL IPV6")
	}
	b.WriteString("\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%-24s %-15s %-28s %12d %12d", r.ss.CommonName(), r.p.ip, r.ss.Remote(), r.ss.RxBytes.Load(), r.ss.TxBytes.Load())
		if v6 {
			fmt.Fprintf(&b, " %s", r.p.ip6)
		}
		b.WriteString("\n")
	}
	tmp := s.cfg.StatusFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err == nil {
		os.Rename(tmp, s.cfg.StatusFile)
	} else {
		s.log.Warn("writing status file", "err", err)
	}
}
