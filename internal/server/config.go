package server

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/ovpn"
	"github.com/softvpn/softvpn/internal/pki"
)

// Directives understood by the server. They follow OpenVPN's server.conf.
var directives = []string{
	"port", "proto", "local", "dev", "server", "server-ipv6", "topology", "ca", "cert", "key",
	"route", "route-ipv6",
	"client-to-client", "duplicate-cn", "keepalive", "push", "client-config-dir",
	"max-clients", "data-ciphers", "ncp-ciphers", "tun-mtu", "status", "verb",
	"server-bridge", "dev-type", "lladdr",
	// softvpn extensions
	"upstream-dns", "nat-allow", "nat-deny",
}

// Directives that only make sense for a kernel-based OpenVPN, accepted so an
// existing server.conf works unchanged.
var ignored = []string{
	"dh", "persist-key", "persist-tun", "user", "group", "cipher", "auth",
	"explicit-exit-notify", "ifconfig-pool-persist", "tls-server", "mode",
	"data-ciphers-fallback", "tls-version-min", "remote-cert-tls", "mute",
	"log", "log-append", "daemon", "script-security", "sndbuf", "rcvbuf",
	"txqueuelen", "fast-io", "mssfix", "tun-mtu-extra",
}

// Listener is one transport the server accepts clients on.
type Listener struct {
	Proto   string // "udp" or "tcp"
	Network string // Go network: "udp" (dual-stack), "udp4", "tcp" or "tcp4"
	Addr    string
}

// Config is the parsed server configuration.
type Config struct {
	Listeners      []Listener
	Subnet         netip.Prefix
	Gateway        netip.Addr
	Subnet6        netip.Prefix // server-ipv6; invalid if IPv6 is off
	Gateway6       netip.Addr
	Routes         []netip.Prefix // route, route-ipv6: networks behind clients
	TLS            *tls.Config
	Ciphers        []string
	ClientToClient bool
	DuplicateCN    bool
	PingInterval   time.Duration
	PingTimeout    time.Duration
	MTU            int
	MaxClients     int
	Push           []string
	CCDDir         string
	UpstreamDNS    string // resolver that DNS sent to the gateway is relayed to
	NATAllow       []netip.Prefix
	NATDeny        []netip.Prefix
	StatusFile     string
	StatusInterval time.Duration
	Verb           int
	Auth           AuthConfig

	// TAP (bridged) mode: clients exchange Ethernet frames over a virtual
	// switch; see bridge.go.
	TAP       bool
	PoolStart netip.Addr // server-bridge address range (else the whole subnet)
	PoolEnd   netip.Addr
	DHCP      bool // server-bridge without arguments: addresses only by DHCP
	NoGateway bool // server-bridge nogw: no route-gateway, no DHCP router
	MAC       net.HardwareAddr
}

// Load validates directives and builds a server Config.
func Load(c *config.Config) (*Config, error) {
	if err := rejectScripts(c); err != nil {
		return nil, err
	}
	if err := c.Check(append(append(directives, authDirectives...), ignored...)...); err != nil {
		return nil, err
	}
	cfg := &Config{
		ClientToClient: c.Has("client-to-client"),
		DuplicateCN:    c.Has("duplicate-cn"),
		PingInterval:   10 * time.Second,
		PingTimeout:    60 * time.Second,
		StatusInterval: 60 * time.Second,
		CCDDir:         c.String("client-config-dir", ""),
	}
	var err error
	if cfg.Verb, err = c.Int("verb", 1); err != nil {
		return nil, err
	}

	port := c.String("port", "1194")
	local := c.String("local", "")
	protos := c.All("proto")
	if len(protos) == 0 {
		protos = []config.Directive{{Name: "proto", Args: []string{"udp"}}}
	}
	for _, d := range protos {
		// As in OpenVPN 2.4+, udp/tcp and udp6/tcp6 listen dual-stack: on
		// IPv6 and IPv4 when the host has IPv6 (unless "local" names one
		// address), otherwise on IPv4. udp4/tcp4 listen on IPv4 only.
		name := strings.TrimSuffix(strings.ToLower(d.Arg(0)), "-server")
		var p string
		switch name {
		case "udp", "udp4", "udp6":
			p = "udp"
		case "tcp", "tcp4", "tcp6":
			p = "tcp"
		default:
			return nil, d.Errorf("unsupported protocol %q (use udp, udp4, udp6, tcp, tcp4 or tcp6)", d.Arg(0))
		}
		network := strings.TrimSuffix(name, "6")
		cfg.Listeners = append(cfg.Listeners, Listener{Proto: p, Network: network, Addr: net.JoinHostPort(local, port)})
	}

	// The device type comes from dev-type, or else the dev name (tun0, tap).
	if d, ok := c.Last("dev"); ok {
		switch {
		case strings.HasPrefix(d.Arg(0), "tun"):
		case strings.HasPrefix(d.Arg(0), "tap"):
			cfg.TAP = true
		default:
			if !c.Has("dev-type") {
				return nil, d.Errorf("cannot tell the device type of %q (use tun or tap, or set dev-type)", d.Arg(0))
			}
		}
	}
	if d, ok := c.Last("dev-type"); ok {
		switch d.Arg(0) {
		case "tun":
			cfg.TAP = false
		case "tap":
			cfg.TAP = true
		default:
			return nil, d.Errorf("dev-type must be tun or tap")
		}
	}
	if d, ok := c.Last("topology"); ok && d.Arg(0) != "subnet" && !cfg.TAP {
		return nil, d.Errorf("only \"topology subnet\" is supported")
	}

	// server 10.8.0.0 255.255.255.0  or  server 10.8.0.0/24
	subnet := "10.8.0.0/24"
	if d, ok := c.Last("server"); ok {
		switch len(d.Args) {
		case 1:
			subnet = d.Args[0]
		case 2:
			mask := net.IPMask(net.ParseIP(d.Args[1]).To4())
			ones, bits := mask.Size()
			if bits != 32 {
				return nil, d.Errorf("invalid netmask %q", d.Args[1])
			}
			subnet = fmt.Sprintf("%s/%d", d.Args[0], ones)
		default:
			return nil, d.Errorf("expects NETWORK NETMASK")
		}
	}
	p, err := netip.ParsePrefix(subnet)
	if err != nil || !p.Addr().Is4() || p.Bits() > 29 {
		return nil, fmt.Errorf("server: invalid IPv4 subnet %q (need /29 or larger)", subnet)
	}
	cfg.Subnet = p.Masked()
	cfg.Gateway = cfg.Subnet.Addr().Next()
	if err := cfg.loadBridge(c); err != nil {
		return nil, err
	}

	// server-ipv6 fd00:8::/64: the gateway is ::1 and each client's address
	// is derived from its IPv4 one, starting at ::1000 like OpenVPN's pool.
	if d, ok := c.Last("server-ipv6"); ok {
		p6, err := netip.ParsePrefix(d.Arg(0))
		if err != nil || !p6.Addr().Is6() || p6.Addr().Is4In6() || p6.Bits() > 112 {
			return nil, d.Errorf("expects an IPv6 PREFIX/LEN of /112 or larger")
		}
		if host := 128 - p6.Bits(); host < 64 && 0x1000+uint64(1)<<(32-cfg.Subnet.Bits()) > uint64(1)<<host {
			return nil, d.Errorf("%s is too small for the IPv4 subnet %s", p6, cfg.Subnet)
		}
		cfg.Subnet6 = p6.Masked()
		cfg.Gateway6 = cfg.Subnet6.Addr().Next()
	}

	// route NETWORK [NETMASK [GATEWAY [METRIC]]] and route-ipv6 PREFIX
	// [GATEWAY [METRIC]]. Kernel OpenVPN installs a kernel route; here they
	// just mark the network as inside the VPN, so it is reached through
	// whichever client has it as an iroute, and never NATed out.
	for _, d := range c.All("route") {
		if len(d.Args) < 1 {
			return nil, d.Errorf("expects NETWORK [NETMASK]")
		}
		pfx, err := parseRoute4(d.Args[0], d.Arg(1))
		if err != nil {
			return nil, d.Errorf("%v", err)
		}
		cfg.Routes = append(cfg.Routes, pfx)
	}
	for _, d := range c.All("route-ipv6") {
		pfx, err := parseRoute6(d.Arg(0))
		if err != nil {
			return nil, d.Errorf("%v", err)
		}
		cfg.Routes = append(cfg.Routes, pfx)
	}
	if cfg.TAP && (cfg.Subnet6.IsValid() || len(cfg.Routes) > 0) {
		return nil, fmt.Errorf("server-ipv6, route and route-ipv6 are not supported with dev tap")
	}

	if cfg.MTU, err = c.Int("tun-mtu", 1500); err != nil {
		return nil, err
	}
	if cfg.MTU < 576 || cfg.MTU > 65535 {
		return nil, fmt.Errorf("tun-mtu must be between 576 and 65535")
	}
	if cfg.MaxClients, err = c.Int("max-clients", 0); err != nil {
		return nil, err
	}

	if d, ok := c.Last("keepalive"); ok {
		if len(d.Args) != 2 {
			return nil, d.Errorf("expects INTERVAL TIMEOUT")
		}
		if cfg.PingInterval, err = config.Seconds(d.Args[0]); err != nil {
			return nil, d.Errorf("%v", err)
		}
		if cfg.PingTimeout, err = config.Seconds(d.Args[1]); err != nil {
			return nil, d.Errorf("%v", err)
		}
		if cfg.PingTimeout <= cfg.PingInterval {
			return nil, d.Errorf("timeout must exceed interval")
		}
	}

	cfg.Ciphers = ovpn.SupportedCiphers
	for _, name := range []string{"ncp-ciphers", "data-ciphers"} {
		if d, ok := c.Last(name); ok {
			cfg.Ciphers = nil
			for _, ci := range strings.Split(d.Arg(0), ":") {
				if !supported(ci) {
					return nil, d.Errorf("unsupported cipher %q (supported: %s)", ci, strings.Join(ovpn.SupportedCiphers, ":"))
				}
				cfg.Ciphers = append(cfg.Ciphers, strings.ToUpper(ci))
			}
		}
	}

	for _, d := range c.All("push") {
		if len(d.Args) != 1 {
			return nil, d.Errorf("expects one quoted option")
		}
		cfg.Push = append(cfg.Push, d.Args[0])
	}

	cfg.UpstreamDNS = c.String("upstream-dns", "")
	if cfg.UpstreamDNS == "" {
		cfg.UpstreamDNS = systemResolver()
	}
	if cfg.UpstreamDNS != "" {
		cfg.UpstreamDNS = withPort(cfg.UpstreamDNS, "53")
	}

	for _, kind := range []string{"nat-allow", "nat-deny"} {
		for _, d := range c.All(kind) {
			for _, a := range d.Args {
				pfx, err := parsePrefix(a)
				if err != nil {
					return nil, d.Errorf("%v", err)
				}
				if kind == "nat-allow" {
					cfg.NATAllow = append(cfg.NATAllow, pfx)
				} else {
					cfg.NATDeny = append(cfg.NATDeny, pfx)
				}
			}
		}
	}

	if d, ok := c.Last("status"); ok {
		cfg.StatusFile = d.Arg(0)
		if s := d.Arg(1); s != "" {
			if cfg.StatusInterval, err = config.Seconds(s); err != nil {
				return nil, d.Errorf("%v", err)
			}
		}
	}

	ca, err := c.Material("ca")
	if err != nil {
		return nil, err
	}
	cert, err := c.Material("cert")
	if err != nil {
		return nil, err
	}
	key, err := c.Material("key")
	if err != nil {
		return nil, err
	}
	if cfg.TLS, err = pki.ServerTLS(ca, cert, key); err != nil {
		return nil, err
	}
	if cfg.Auth, err = loadAuth(c, ca, cfg.TLS); err != nil {
		return nil, err
	}
	return cfg, nil
}

func supported(cipher string) bool {
	for _, s := range ovpn.SupportedCiphers {
		if strings.EqualFold(s, cipher) {
			return true
		}
	}
	return false
}

// parseRoute4 parses an IPv4 route as OpenVPN writes it, NETWORK [NETMASK]
// (a missing netmask means a host route), or as NETWORK/BITS.
func parseRoute4(network, netmask string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(network, "/") {
		var err error
		if p, err = netip.ParsePrefix(network); err != nil {
			return p, fmt.Errorf("invalid IPv4 route %q", network)
		}
	} else {
		if netmask == "" {
			netmask = "255.255.255.255"
		}
		ip, err := netip.ParseAddr(network)
		ones, bits := net.IPMask(net.ParseIP(netmask).To4()).Size()
		if err != nil || bits != 32 {
			return p, fmt.Errorf("invalid IPv4 route %q %q", network, netmask)
		}
		p = netip.PrefixFrom(ip, ones)
	}
	if !p.Addr().Is4() {
		return p, fmt.Errorf("invalid IPv4 route %q", network)
	}
	if p.Masked() != p {
		return p, fmt.Errorf("%s has host bits set (network is %s)", p, p.Masked())
	}
	return p, nil
}

// parseRoute6 parses an IPv6 route, PREFIX/BITS.
func parseRoute6(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
		return p, fmt.Errorf("invalid IPv6 route %q (expects PREFIX/BITS)", s)
	}
	if p.Masked() != p {
		return p, fmt.Errorf("%s has host bits set (network is %s)", p, p.Masked())
	}
	return p, nil
}

// internal reports whether a belongs inside the VPN: the client subnets and
// the networks declared with route/route-ipv6. Such addresses are routed to
// clients or dropped, never NATed out.
func (cfg *Config) internal(a netip.Addr) bool {
	if cfg.Subnet.Contains(a) || cfg.Subnet6.Contains(a) {
		return true
	}
	for _, p := range cfg.Routes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ipv6For derives a client's IPv6 address from its IPv4 one: the first
// pool address (gateway+1) maps to PREFIX::1000, the next to ::1001, and so
// on, matching OpenVPN's ifconfig-ipv6-pool numbering.
func (cfg *Config) ipv6For(ip netip.Addr) netip.Prefix {
	if !cfg.Subnet6.IsValid() {
		return netip.Prefix{}
	}
	a4, n4 := ip.As4(), cfg.Subnet.Addr().As4()
	off := uint64(binary.BigEndian.Uint32(a4[:]) - binary.BigEndian.Uint32(n4[:]) - 2)
	b := cfg.Subnet6.Addr().As16()
	binary.BigEndian.PutUint64(b[8:], binary.BigEndian.Uint64(b[8:])+0x1000+off)
	return netip.PrefixFrom(netip.AddrFrom16(b), cfg.Subnet6.Bits())
}

func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address or prefix %q", s)
	}
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

// systemResolver returns the first nameserver in /etc/resolv.conf. In a
// Docker container this is typically Docker's embedded DNS (127.0.0.11), so
// clients can resolve the same names the server can.
func systemResolver() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip, err := netip.ParseAddr(fields[1]); err == nil {
				return netip.AddrPortFrom(ip.WithZone(""), 53).String()
			}
		}
	}
	return ""
}

// withPort appends port to addr unless it already has one.
func withPort(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), port)
}

// clientConfig is the per-client override file in client-config-dir.
type clientConfig struct {
	IP       netip.Addr
	IP6      netip.Prefix // ifconfig-ipv6-push ADDR/BITS
	IRoutes  []netip.Prefix
	Push     []string
	NoPush   bool // push-reset
	Disabled bool
}

func (cfg *Config) loadCCD(cn string) (*clientConfig, error) {
	cc := &clientConfig{}
	if cfg.CCDDir == "" || cn == "" || strings.ContainsAny(cn, "/\\") || cn[0] == '.' {
		return cc, nil
	}
	path := cfg.CCDDir + "/" + cn
	if _, err := os.Stat(path); err != nil {
		return cc, nil
	}
	c, err := config.ParseFile(path)
	if err != nil {
		return nil, err
	}
	if err := c.Check("ifconfig-push", "ifconfig-ipv6-push", "push", "push-reset", "disable", "iroute", "iroute-ipv6"); err != nil {
		return nil, err
	}
	cc.Disabled = c.Has("disable")
	cc.NoPush = c.Has("push-reset")
	for _, d := range c.All("push") {
		cc.Push = append(cc.Push, d.Arg(0))
	}
	if d, ok := c.Last("ifconfig-push"); ok {
		ip, err := netip.ParseAddr(d.Arg(0))
		if err != nil || !cfg.Subnet.Contains(ip) || ip == cfg.Gateway || ip == cfg.Subnet.Addr() {
			return nil, d.Errorf("%q is not a usable address in %s", d.Arg(0), cfg.Subnet)
		}
		cc.IP = ip
	}
	// ifconfig-ipv6-push ADDR/BITS [REMOTE]: the remote end is always the
	// server's gateway, so a second argument is accepted and ignored.
	if d, ok := c.Last("ifconfig-ipv6-push"); ok {
		if !cfg.Subnet6.IsValid() {
			return nil, d.Errorf("needs server-ipv6 in the server configuration")
		}
		p, err := netip.ParsePrefix(d.Arg(0))
		if err != nil || !cfg.Subnet6.Contains(p.Addr()) || p.Addr() == cfg.Gateway6 || p.Addr() == cfg.Subnet6.Addr() {
			return nil, d.Errorf("%q is not a usable ADDRESS/BITS in %s", d.Arg(0), cfg.Subnet6)
		}
		cc.IP6 = p
	}
	// iroute NETWORK [NETMASK] and iroute-ipv6 PREFIX: networks behind this
	// client, routed to it.
	for _, d := range c.All("iroute") {
		p, err := parseRoute4(d.Arg(0), d.Arg(1))
		if err != nil {
			return nil, d.Errorf("%v", err)
		}
		cc.IRoutes = append(cc.IRoutes, p)
	}
	for _, d := range c.All("iroute-ipv6") {
		p, err := parseRoute6(d.Arg(0))
		if err != nil {
			return nil, d.Errorf("%v", err)
		}
		cc.IRoutes = append(cc.IRoutes, p)
	}
	if len(cc.IRoutes) > 0 && cfg.TAP {
		return nil, fmt.Errorf("%s: iroute is not supported with dev tap", path)
	}
	for _, p := range cc.IRoutes {
		if p.Overlaps(cfg.Subnet) || p.Overlaps(cfg.Subnet6) {
			return nil, fmt.Errorf("%s: iroute %s overlaps the VPN subnet", path, p)
		}
	}
	return cc, nil
}
