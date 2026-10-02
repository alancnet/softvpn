package server

import (
	"bufio"
	"crypto/tls"
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
	"port", "proto", "local", "dev", "server", "topology", "ca", "cert", "key",
	"client-to-client", "duplicate-cn", "keepalive", "push", "client-config-dir",
	"max-clients", "data-ciphers", "ncp-ciphers", "tun-mtu", "status", "verb",
	"tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction", "auth",
	// softvpn extensions
	"upstream-dns", "nat-allow", "nat-deny",
}

// Directives that only make sense for a kernel-based OpenVPN, accepted so an
// existing server.conf works unchanged.
var ignored = []string{
	"dh", "persist-key", "persist-tun", "user", "group", "cipher",
	"explicit-exit-notify", "ifconfig-pool-persist", "tls-server", "mode",
	"data-ciphers-fallback", "tls-version-min", "remote-cert-tls", "mute",
	"log", "log-append", "daemon", "script-security", "sndbuf", "rcvbuf",
	"txqueuelen", "fast-io", "mssfix", "tun-mtu-extra", "dev-type",
}

// Listener is one transport the server accepts clients on.
type Listener struct {
	Proto string // "udp" or "tcp"
	Addr  string
}

// Config is the parsed server configuration.
type Config struct {
	Listeners      []Listener
	Subnet         netip.Prefix
	Gateway        netip.Addr
	TLS            *tls.Config
	Wrap           *ovpn.ControlWrap // tls-auth / tls-crypt / tls-crypt-v2
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
}

// Load validates directives and builds a server Config.
func Load(c *config.Config) (*Config, error) {
	if err := c.Check(append(directives, ignored...)...); err != nil {
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
		var p string
		switch strings.ToLower(d.Arg(0)) {
		case "udp", "udp4":
			p = "udp"
		case "tcp", "tcp4", "tcp-server", "tcp4-server":
			p = "tcp"
		default:
			return nil, d.Errorf("unsupported protocol %q (use udp or tcp)", d.Arg(0))
		}
		cfg.Listeners = append(cfg.Listeners, Listener{Proto: p, Addr: net.JoinHostPort(local, port)})
	}

	if d, ok := c.Last("dev"); ok && !strings.HasPrefix(d.Arg(0), "tun") {
		return nil, d.Errorf("only routed (tun) mode is supported")
	}
	if d, ok := c.Last("topology"); ok && d.Arg(0) != "subnet" {
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
	if cfg.Wrap, err = controlWrap(c); err != nil {
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
	if err := c.Check("ifconfig-push", "push", "push-reset", "disable", "iroute"); err != nil {
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
	if len(c.All("iroute")) > 0 {
		return nil, fmt.Errorf("%s: iroute is not supported", path)
	}
	return cc, nil
}
