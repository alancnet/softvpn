package server

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/softvpn/softvpn/internal/ovpn"
)

func TestRoutes(t *testing.T) {
	r := newRoutes()
	a, b, c := new(ovpn.Session), new(ovpn.Session), new(ovpn.Session)
	pfx := netip.MustParsePrefix
	addr := netip.MustParseAddr

	r.add(pfx("10.8.0.2/32"), a)
	r.add(pfx("fd00:8::1000/128"), a)
	r.add(pfx("192.168.0.0/16"), b)
	r.add(pfx("192.168.1.0/24"), c)
	r.add(pfx("fd00:30::/64"), c)
	r.add(pfx("0.0.0.0/0"), a)

	for _, tc := range []struct {
		ip   string
		want *ovpn.Session
	}{
		{"10.8.0.2", a},
		{"fd00:8::1000", a},
		{"192.168.1.7", c}, // longest prefix wins
		{"192.168.2.7", b},
		{"fd00:30::5", c},
		{"8.8.8.8", a}, // iroute 0.0.0.0/0
		{"fd00:31::5", nil},
	} {
		if got := r.lookup(addr(tc.ip)); got != tc.want {
			t.Errorf("lookup(%s) = %p, want %p", tc.ip, got, tc.want)
		}
	}

	// The client that connects last owns a contested route; the previous
	// owner disconnecting later must not remove it.
	if prev := r.add(pfx("192.168.1.0/24"), b); prev != c {
		t.Fatalf("add returned previous owner %p, want %p", prev, c)
	}
	r.remove(pfx("192.168.1.0/24"), c)
	if got := r.lookup(addr("192.168.1.7")); got != b {
		t.Fatalf("route removed by its former owner")
	}
	r.remove(pfx("192.168.1.0/24"), b)
	r.remove(pfx("0.0.0.0/0"), a)
	if got := r.lookup(addr("192.168.1.7")); got != b {
		t.Fatalf("after removing /24: got %p, want the /16 owner", got)
	}
	r.remove(pfx("10.8.0.2/32"), b) // not the owner
	if r.lookup(addr("10.8.0.2")) != a {
		t.Fatal("host route removed by a session that does not own it")
	}
	r.remove(pfx("10.8.0.2/32"), a)
	if r.lookup(addr("10.8.0.2")) != nil {
		t.Fatal("host route not removed")
	}
}

func TestParseIP(t *testing.T) {
	v4 := make([]byte, 28)
	v4[0], v4[9] = 0x45, protoICMP
	copy(v4[12:], []byte{10, 8, 0, 2, 1, 2, 3, 4})
	h, ok := parseIP(v4)
	if !ok || h.src.String() != "10.8.0.2" || h.dst.String() != "1.2.3.4" || h.proto != protoICMP || h.payload != 20 {
		t.Fatalf("IPv4: %+v %v", h, ok)
	}

	src, dst := netip.MustParseAddr("fd00:8::1000"), netip.MustParseAddr("2001:db8::1")
	echo := []byte{icmpv6EchoRequest, 0, 0, 0, 0, 1, 0, 1}
	v6 := ipv6Packet(src, dst, protoICMPv6, echo)
	h, ok = parseIP(v6)
	if !ok || h.src != src || h.dst != dst || h.proto != protoICMPv6 || h.payload != 40 || !h.isEcho6(v6) {
		t.Fatalf("IPv6: %+v %v", h, ok)
	}

	// Hop-by-hop options (8 bytes) in front of the ICMPv6 header.
	hbh := append([]byte{protoICMPv6, 0, 1, 4, 0, 0, 0, 0}, echo...)
	v6 = ipv6Packet(src, dst, ipv6HopByHop, hbh)
	h, ok = parseIP(v6)
	if !ok || h.proto != protoICMPv6 || h.payload != 48 || !h.isEcho6(v6) {
		t.Fatalf("IPv6 with extension header: %+v %v", h, ok)
	}

	for name, pkt := range map[string][]byte{
		"empty":         nil,
		"short IPv4":    v4[:19],
		"bad IHL":       append([]byte{0x41}, v4[1:]...),
		"short IPv6":    v6[:39],
		"truncated ext": v6[:41],
		"version 5":     append([]byte{0x50}, v4[1:]...),
	} {
		if _, ok := parseIP(pkt); ok {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestIPv6Packet(t *testing.T) {
	src, dst := netip.MustParseAddr("fd00:8::1"), netip.MustParseAddr("fd00:8::1000")
	p := ipv6Packet(src, dst, protoICMPv6, []byte{129, 0, 0, 0})
	if p[0]>>4 != 6 || binary.BigEndian.Uint16(p[4:]) != 4 || p[6] != protoICMPv6 || len(p) != 44 {
		t.Fatalf("bad header % x", p[:8])
	}
}

func TestLoadIPv6AndRoutes(t *testing.T) {
	dir := testPKI(t)
	cfg, err := load(dir, `
server 10.8.0.0 255.255.255.0
server-ipv6 fd00:8::/64
proto udp
proto udp6
proto tcp4-server
proto tcp6
route 192.168.10.0 255.255.255.0
route 172.16.5.0/24 vpn_gateway 10
route 10.99.0.1
route-ipv6 fd00:30::/64
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Subnet6.String() != "fd00:8::/64" || cfg.Gateway6.String() != "fd00:8::1" {
		t.Fatalf("subnet6 %s gateway6 %s", cfg.Subnet6, cfg.Gateway6)
	}
	var nets []string
	for _, l := range cfg.Listeners {
		nets = append(nets, l.Proto+"/"+l.Network)
	}
	if got := strings.Join(nets, " "); got != "udp/udp udp/udp tcp/tcp4 tcp/tcp" {
		t.Fatalf("listeners: %s", got)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.168.10.0/24"), netip.MustParsePrefix("172.16.5.0/24"),
		netip.MustParsePrefix("10.99.0.1/32"), netip.MustParsePrefix("fd00:30::/64"),
	}
	if !reflect.DeepEqual(cfg.Routes, want) {
		t.Fatalf("routes %v", cfg.Routes)
	}
	for ip, internal := range map[string]bool{
		"10.8.0.7": true, "fd00:8::1234": true, "192.168.10.9": true, "fd00:30::1": true,
		"192.168.11.1": false, "2001:db8::1": false, "10.99.0.2": false,
	} {
		if cfg.internal(netip.MustParseAddr(ip)) != internal {
			t.Errorf("internal(%s) != %v", ip, internal)
		}
	}
	for v4, v6 := range map[string]string{"10.8.0.2": "fd00:8::1000/64", "10.8.0.20": "fd00:8::1012/64", "10.8.0.254": "fd00:8::10fc/64"} {
		if got := cfg.ipv6For(netip.MustParseAddr(v4)); got.String() != v6 {
			t.Errorf("ipv6For(%s) = %s, want %s", v4, got, v6)
		}
	}

	for _, bad := range []string{
		"server-ipv6 fd00:8::/120",                              // smaller than /112
		"server 10.8.0.0 255.255.0.0\nserver-ipv6 fd00:8::/112", // pool doesn't fit
		"server-ipv6 10.0.0.0/8",
		"route 192.168.10.1 255.255.255.0", // host bits
		"route-ipv6 fd00:30::1/64",
		"route-ipv6 192.168.0.0/16",
		"proto sctp",
		"dev tap\nserver-ipv6 fd00:8::/64", // IPv4 only in TAP mode
		"dev tap\nroute 192.168.10.0 255.255.255.0",
	} {
		if _, err := load(dir, bad+"\n"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestClientConfigIPv6AndIRoute(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{
		Subnet: netip.MustParsePrefix("10.8.0.0/24"), Gateway: netip.MustParseAddr("10.8.0.1"),
		Subnet6: netip.MustParsePrefix("fd00:8::/64"), Gateway6: netip.MustParseAddr("fd00:8::1"),
		CCDDir: dir,
	}
	write("site", `ifconfig-push 10.8.0.20 255.255.255.0
ifconfig-ipv6-push fd00:8::20/64 fd00:8::1
iroute 192.168.30.0 255.255.255.0
iroute 192.168.31.5
iroute-ipv6 fd00:30::/64
`)
	cc, err := cfg.loadCCD("site")
	if err != nil {
		t.Fatal(err)
	}
	if cc.IP6.String() != "fd00:8::20/64" {
		t.Fatalf("ifconfig-ipv6-push: %s", cc.IP6)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.168.30.0/24"), netip.MustParsePrefix("192.168.31.5/32"), netip.MustParsePrefix("fd00:30::/64"),
	}
	if !reflect.DeepEqual(cc.IRoutes, want) {
		t.Fatalf("iroutes %v", cc.IRoutes)
	}

	for i, bad := range []string{
		"iroute 10.8.0.0 255.255.0.0", // overlaps the VPN subnet
		"iroute-ipv6 fd00:8::/48",
		"iroute 192.168.30.1 255.255.255.0",
		"iroute-ipv6 nonsense",
		"ifconfig-ipv6-push fd00:9::5/64",
		"ifconfig-ipv6-push fd00:8::1/64", // the gateway
	} {
		name := "bad" + string(rune('a'+i))
		write(name, bad+"\n")
		if _, err := cfg.loadCCD(name); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	cfg.Subnet6, cfg.Gateway6 = netip.Prefix{}, netip.Addr{}
	write("v6off", "ifconfig-ipv6-push fd00:8::20/64\n")
	if _, err := cfg.loadCCD("v6off"); err == nil {
		t.Error("ifconfig-ipv6-push accepted without server-ipv6")
	}
}

func TestWithoutOwnRoutes(t *testing.T) {
	push := []string{
		"redirect-gateway def1",
		"route 192.168.30.0 255.255.255.0",
		"route 192.168.30.128 255.255.255.128 vpn_gateway",
		"route 192.168.40.0 255.255.255.0",
		"route-ipv6 fd00:30::/64",
		"route-ipv6 fd00:40::/64",
		"route 192.168.30.7",
	}
	iroutes := []netip.Prefix{netip.MustParsePrefix("192.168.30.0/24"), netip.MustParsePrefix("fd00:30::/48")}
	got := withoutOwnRoutes(push, iroutes)
	want := []string{"redirect-gateway def1", "route 192.168.40.0 255.255.255.0", "route-ipv6 fd00:40::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
	if got := withoutOwnRoutes(push, nil); !reflect.DeepEqual(got, push) {
		t.Fatal("pushes changed for a client without iroutes")
	}
}

func TestPolicyIPv6(t *testing.T) {
	s := &Server{cfg: &Config{
		Subnet: netip.MustParsePrefix("10.8.0.0/24"), Gateway: netip.MustParseAddr("10.8.0.1"),
		Subnet6: netip.MustParsePrefix("fd00:8::/64"), Gateway6: netip.MustParseAddr("fd00:8::1"),
		Routes:      []netip.Prefix{netip.MustParsePrefix("fd00:30::/64"), netip.MustParsePrefix("192.168.30.0/24")},
		UpstreamDNS: "127.0.0.11:53",
	}}
	src := netip.MustParseAddrPort("[fd00:8::1000]:40000")
	for dst, want := range map[string]string{
		"[2001:db8::1]:443":         "[2001:db8::1]:443",
		"[fd00:8::1]:53":            "127.0.0.11:53", // DNS to the IPv6 gateway
		"[fd00:8::1]:80":            "",
		"[fd00:8::1001]:80":         "", // another client
		"[fd00:30::5]:80":           "", // a network behind a client
		"192.168.30.5:80":           "",
		"[::1]:80":                  "",
		"[::]:80":                   "",
		"[fe80::1]:80":              "",
		"[ff02::1]:80":              "",
		"[::ffff:127.0.0.1]:80":     "",
		"[::ffff:93.184.216.34]:80": "",
		"93.184.216.34:80":          "93.184.216.34:80",
	} {
		got, ok := s.policy("tcp", src, netip.MustParseAddrPort(dst))
		if !ok {
			got = ""
		}
		if got != want {
			t.Errorf("policy(%s) = %q, want %q", dst, got, want)
		}
	}
}
