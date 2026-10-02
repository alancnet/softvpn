package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/pki"
)

type fakePort struct {
	cn  string
	mu  sync.Mutex
	got [][]byte
}

func (p *fakePort) SendPacket(f []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got = append(p.got, append([]byte(nil), f...))
}
func (p *fakePort) CommonName() string { return p.cn }

// take returns and clears the frames the port received.
func (p *fakePort) take() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	g := p.got
	p.got = nil
	return g
}

var (
	testGW    = netip.MustParseAddr("10.9.0.1")
	testGWMAC = mac{0x02, 0, 10, 9, 0, 1}
	macA      = mac{0x52, 0x54, 0, 0, 0, 0xa}
	macB      = mac{0x52, 0x54, 0, 0, 0, 0xb}
	macC      = mac{0x52, 0x54, 0, 0, 0, 0xc}
	ipA       = netip.MustParseAddr("10.9.0.100")
	ipB       = netip.MustParseAddr("10.9.0.101")
	ipC       = netip.MustParseAddr("10.9.0.102")
)

type testBridge struct {
	*bridge
	a, b, c *fakePort
	mu      sync.Mutex
	local   [][]byte
}

func newTestBridge(c2c bool) *testBridge {
	tb := &testBridge{a: &fakePort{cn: "a"}, b: &fakePort{cn: "b"}, c: &fakePort{cn: "c"}}
	tb.bridge = newBridge(bridgeOptions{
		MAC:            net.HardwareAddr(testGWMAC[:]),
		Gateway:        testGW,
		Subnet:         netip.MustParsePrefix("10.9.0.0/24"),
		ClientToClient: c2c,
		DHCPRouter:     true,
		Local: func(pkt []byte) {
			tb.mu.Lock()
			tb.local = append(tb.local, append([]byte(nil), pkt...))
			tb.mu.Unlock()
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	tb.attach(tb.a, ipA, []string{"dhcp-option DNS 10.9.0.1", "dhcp-option DOMAIN vpn.test"})
	tb.attach(tb.b, ipB, nil)
	tb.attach(tb.c, ipC, nil)
	return tb
}

func (tb *testBridge) takeLocal() [][]byte {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	l := tb.local
	tb.local = nil
	return l
}

func (tb *testBridge) takeAll() {
	tb.a.take()
	tb.b.take()
	tb.c.take()
	tb.takeLocal()
}

func ether(dst, src mac, typ uint16, payload []byte) []byte {
	f := make([]byte, etherHdrLen, etherHdrLen+len(payload))
	copy(f[0:6], dst[:])
	copy(f[6:12], src[:])
	binary.BigEndian.PutUint16(f[12:], typ)
	return append(f, payload...)
}

func arp(op uint16, sha mac, spa netip.Addr, tha mac, tpa netip.Addr) []byte {
	a := make([]byte, arpLen)
	binary.BigEndian.PutUint16(a[0:], 1)
	binary.BigEndian.PutUint16(a[2:], etherIPv4)
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:], op)
	s, t := spa.As4(), tpa.As4()
	copy(a[8:14], sha[:])
	copy(a[14:18], s[:])
	copy(a[18:24], tha[:])
	copy(a[24:28], t[:])
	return a
}

func udpPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	return ipv4Packet(src, dst, 17, udpDatagram(src, dst, sport, dport, payload))
}

func TestBridgeARPForGateway(t *testing.T) {
	tb := newTestBridge(true)
	tb.input(tb.a, ether(broadcastMAC, macA, etherARP, arp(1, macA, ipA, mac{}, testGW)))
	got := tb.a.take()
	if len(got) != 1 {
		t.Fatalf("expected one ARP reply, got %d frames", len(got))
	}
	r := got[0]
	if macOf(r[0:6]) != macA || macOf(r[6:12]) != testGWMAC || binary.BigEndian.Uint16(r[12:]) != etherARP {
		t.Fatalf("bad reply header % x", r[:14])
	}
	a := r[etherHdrLen:]
	if binary.BigEndian.Uint16(a[6:]) != 2 || macOf(a[8:14]) != testGWMAC || addr4(a[14:18]) != testGW ||
		macOf(a[18:24]) != macA || addr4(a[24:28]) != ipA {
		t.Fatalf("bad ARP reply % x", a)
	}
	if len(tb.b.take())+len(tb.c.take()) != 0 {
		t.Fatal("ARP request for the gateway was flooded to other clients")
	}
	// A unicast refresh to the gateway's MAC is answered too.
	tb.input(tb.a, ether(testGWMAC, macA, etherARP, arp(1, macA, ipA, testGWMAC, testGW)))
	if len(tb.a.take()) != 1 {
		t.Fatal("unicast ARP request to the gateway not answered")
	}
	// So is an RFC 5227 probe from 0.0.0.0.
	tb.input(tb.a, ether(broadcastMAC, macA, etherARP, arp(1, macA, netip.IPv4Unspecified(), mac{}, testGW)))
	if len(tb.a.take()) != 1 {
		t.Fatal("ARP probe not answered")
	}
}

func TestBridgeSwitching(t *testing.T) {
	tb := newTestBridge(true)
	// a asks for b: flooded to b and c, not back to a.
	tb.input(tb.a, ether(broadcastMAC, macA, etherARP, arp(1, macA, ipA, mac{}, ipB)))
	if len(tb.a.take()) != 0 || len(tb.b.take()) != 1 || len(tb.c.take()) != 1 {
		t.Fatal("broadcast not flooded to the other ports")
	}
	// b answers a: unicast, only to a.
	tb.input(tb.b, ether(macA, macB, etherARP, arp(2, macB, ipB, macA, ipA)))
	if len(tb.a.take()) != 1 || len(tb.c.take()) != 0 {
		t.Fatal("unicast ARP reply not switched to a only")
	}
	// IPv4 a -> b, b's MAC now learned.
	pkt := udpPacket(ipA, ipB, 1000, 2000, []byte("hi"))
	tb.input(tb.a, ether(macB, macA, etherIPv4, pkt))
	if got := tb.b.take(); len(got) != 1 || !bytes.Equal(got[0][etherHdrLen:], pkt) || len(tb.c.take()) != 0 {
		t.Fatal("unicast frame not switched to b only")
	}
	// Unknown unicast (c has not sent anything yet) is flooded.
	tb.input(tb.a, ether(macC, macA, etherIPv4, udpPacket(ipA, ipC, 1000, 2000, nil)))
	if len(tb.b.take()) != 1 || len(tb.c.take()) != 1 {
		t.Fatal("unknown unicast not flooded")
	}
	// Multicast is flooded.
	tb.input(tb.a, ether(mac{0x01, 0, 0x5e, 0, 0, 0xfb}, macA, etherIPv4,
		udpPacket(ipA, netip.MustParseAddr("224.0.0.251"), 5353, 5353, nil)))
	if len(tb.b.take()) != 1 || len(tb.c.take()) != 1 || len(tb.takeLocal()) != 0 {
		t.Fatal("multicast not flooded (or sent to the gateway)")
	}
	// Other ethertypes (IPv6 here) are not bridged.
	tb.input(tb.a, ether(broadcastMAC, macA, 0x86dd, make([]byte, 40)))
	if len(tb.b.take())+len(tb.c.take()) != 0 {
		t.Fatal("IPv6 frame bridged")
	}
	// After b leaves, its MAC is forgotten and can be reused by a new port.
	tb.detach(tb.b)
	d := &fakePort{cn: "d"}
	tb.attach(d, ipB, nil)
	tb.input(d, ether(broadcastMAC, macB, etherARP, arp(1, macB, ipB, mac{}, testGW)))
	if len(d.take()) != 1 {
		t.Fatal("new port could not reuse a departed client's MAC")
	}
}

func TestBridgeNoClientToClient(t *testing.T) {
	tb := newTestBridge(false)
	tb.input(tb.b, ether(broadcastMAC, macB, etherARP, arp(1, macB, ipB, mac{}, testGW)))
	tb.takeAll()
	tb.input(tb.a, ether(broadcastMAC, macA, etherARP, arp(1, macA, ipA, mac{}, ipB)))
	tb.input(tb.a, ether(macB, macA, etherIPv4, udpPacket(ipA, ipB, 1, 2, nil)))
	tb.input(tb.a, ether(broadcastMAC, macA, etherIPv4, udpPacket(ipA, netip.MustParseAddr("10.9.0.255"), 1, 2, nil)))
	if len(tb.b.take())+len(tb.c.take()) != 0 {
		t.Fatal("frames reached other clients without client-to-client")
	}
	// The server side still works.
	tb.input(tb.a, ether(broadcastMAC, macA, etherARP, arp(1, macA, ipA, mac{}, testGW)))
	tb.input(tb.a, ether(testGWMAC, macA, etherIPv4, udpPacket(ipA, netip.MustParseAddr("192.0.2.1"), 1, 2, nil)))
	if len(tb.a.take()) != 1 || len(tb.takeLocal()) != 1 {
		t.Fatal("gateway unreachable without client-to-client")
	}
}

func TestBridgeAntiSpoofing(t *testing.T) {
	tb := newTestBridge(true)
	tb.input(tb.a, ether(broadcastMAC, macA, etherARP, arp(1, macA, ipA, mac{}, testGW)))
	tb.takeAll()
	ext := netip.MustParseAddr("192.0.2.1")
	for name, f := range map[string][]byte{
		"foreign source MAC":          ether(testGWMAC, macC, etherIPv4, udpPacket(ipA, ext, 1, 2, nil)),
		"spoofed source IP":           ether(testGWMAC, macA, etherIPv4, udpPacket(ipB, ext, 1, 2, nil)),
		"unspecified source IP":       ether(testGWMAC, macA, etherIPv4, udpPacket(netip.IPv4Unspecified(), ext, 1, 2, nil)),
		"gateway MAC as source":       ether(broadcastMAC, testGWMAC, etherARP, arp(1, testGWMAC, testGW, mac{}, ipB)),
		"multicast source MAC":        ether(broadcastMAC, broadcastMAC, etherARP, arp(1, macA, ipA, mac{}, ipB)),
		"ARP sender MAC mismatch":     ether(broadcastMAC, macA, etherARP, arp(1, macC, ipA, mac{}, testGW)),
		"ARP sender IP spoofed":       ether(broadcastMAC, macA, etherARP, arp(1, macA, ipB, mac{}, testGW)),
		"ARP reply poisoning gateway": ether(broadcastMAC, macA, etherARP, arp(2, macA, testGW, broadcastMAC, ipB)),
		"rogue DHCP server":           ether(broadcastMAC, macA, etherIPv4, udpPacket(ipA, netip.MustParseAddr("255.255.255.255"), 67, 68, make([]byte, 300))),
		"truncated IPv4":              ether(testGWMAC, macA, etherIPv4, udpPacket(ipA, ext, 1, 2, nil)[:19]),
	} {
		tb.input(tb.a, f)
		if n := len(tb.a.take()) + len(tb.b.take()) + len(tb.c.take()) + len(tb.takeLocal()); n != 0 {
			t.Errorf("%s: %d frames got through", name, n)
		}
	}
	// b cannot claim a's MAC.
	tb.input(tb.b, ether(broadcastMAC, macA, etherARP, arp(1, macA, ipB, mac{}, testGW)))
	if len(tb.b.take())+len(tb.a.take()) != 0 {
		t.Fatal("second port learned a MAC already in use")
	}
}

func TestBridgeGatewayPort(t *testing.T) {
	tb := newTestBridge(true)
	ext := netip.MustParseAddr("192.0.2.1")
	reply := udpPacket(ext, ipA, 2, 1, []byte("pong"))
	tb.output(reply)
	if len(tb.a.take()) != 0 {
		t.Fatal("frame sent before the client's MAC was known")
	}

	// Ethernet padding is trimmed before the packet is routed.
	pkt := udpPacket(ipA, ext, 1, 2, []byte("x"))
	tb.input(tb.a, append(ether(testGWMAC, macA, etherIPv4, pkt), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
	if l := tb.takeLocal(); len(l) != 1 || !bytes.Equal(l[0], pkt) {
		t.Fatalf("gateway port did not receive the packet: %v", l)
	}

	tb.output(reply)
	got := tb.a.take()
	if len(got) != 1 {
		t.Fatalf("expected one frame, got %d", len(got))
	}
	f := got[0]
	if macOf(f[0:6]) != macA || macOf(f[6:12]) != testGWMAC || binary.BigEndian.Uint16(f[12:]) != etherIPv4 ||
		!bytes.Equal(f[etherHdrLen:], reply) {
		t.Fatalf("bad frame % x", f)
	}
	tb.output(udpPacket(ext, netip.MustParseAddr("10.9.0.200"), 2, 1, nil))
	if len(tb.a.take())+len(tb.b.take())+len(tb.c.take()) != 0 {
		t.Fatal("packet for an unknown address was delivered")
	}
}

func dhcpMessage(typ byte, chaddr mac, ciaddr netip.Addr, opts ...byte) []byte {
	m := make([]byte, 240)
	m[0], m[1], m[2] = 1, 1, 6
	copy(m[4:8], []byte{1, 2, 3, 4})
	c := ciaddr.As4()
	copy(m[12:16], c[:])
	copy(m[28:34], chaddr[:])
	copy(m[236:], dhcpMagic)
	m = append(m, optMsgType, 1, typ)
	m = append(m, opts...)
	return append(m, optEnd)
}

// dhcpReply parses the single DHCP reply a port received.
func dhcpReply(t *testing.T, p *fakePort) (yiaddr netip.Addr, dst netip.Addr, opts map[byte][]byte) {
	t.Helper()
	got := p.take()
	if len(got) != 1 {
		t.Fatalf("expected one DHCP reply, got %d frames", len(got))
	}
	pkt, ok := ipv4Payload(got[0][etherHdrLen:])
	if !ok || macOf(got[0][0:6]) != macA {
		t.Fatal("bad DHCP reply frame")
	}
	if checksum(pkt[:20]) != 0 {
		t.Fatal("bad IP checksum")
	}
	sport, dport, ok := udpPorts(pkt)
	if !ok || sport != 67 || dport != 68 {
		t.Fatal("not a DHCP reply")
	}
	m := pkt[28:]
	if m[0] != 2 || !bytes.Equal(m[4:8], []byte{1, 2, 3, 4}) || macOf(m[28:34]) != macA {
		t.Fatal("bad BOOTP reply")
	}
	return addr4(m[16:20]), addr4(pkt[16:20]), parseDHCPOptions(m[240:])
}

func TestBridgeDHCP(t *testing.T) {
	tb := newTestBridge(true)
	any4, bcast := netip.IPv4Unspecified(), netip.MustParseAddr("255.255.255.255")
	send := func(src netip.Addr, m []byte) {
		dst := bcast
		if !src.IsUnspecified() {
			dst = testGW
		}
		tb.input(tb.a, ether(broadcastMAC, macA, etherIPv4, udpPacket(src, dst, 68, 67, m)))
	}

	send(any4, dhcpMessage(dhcpDiscover, macA, any4))
	yi, _, o := dhcpReply(t, tb.a)
	if yi != ipA || o[optMsgType][0] != dhcpOffer || addr4(o[optServerID]) != testGW ||
		!bytes.Equal(o[optMask], []byte{255, 255, 255, 0}) || addr4(o[optRouter]) != testGW ||
		addr4(o[optDNS]) != testGW || string(o[optDomain]) != "vpn.test" || len(o[optLease]) != 4 {
		t.Fatalf("bad offer: yiaddr %s, options %v", yi, o)
	}
	if len(tb.b.take())+len(tb.c.take()) != 0 {
		t.Fatal("DHCP discover flooded to other clients")
	}

	gw := testGW.As4()
	want := ipA.As4()
	send(any4, dhcpMessage(dhcpRequest, macA, any4, append([]byte{optReqIP, 4}, append(want[:], append([]byte{optServerID, 4}, gw[:]...)...)...)...))
	if yi, _, o := dhcpReply(t, tb.a); yi != ipA || o[optMsgType][0] != dhcpAck {
		t.Fatalf("request not acknowledged: %s %v", yi, o)
	}

	other := ipB.As4()
	send(any4, dhcpMessage(dhcpRequest, macA, any4, append([]byte{optReqIP, 4}, other[:]...)...))
	if _, dst, o := dhcpReply(t, tb.a); o[optMsgType][0] != dhcpNak || dst != bcast {
		t.Fatalf("request for someone else's address not refused: %v", o)
	}

	// Renewal: unicast from the client's own address.
	send(ipA, dhcpMessage(dhcpRequest, macA, ipA))
	if yi, dst, o := dhcpReply(t, tb.a); yi != ipA || dst != ipA || o[optMsgType][0] != dhcpAck {
		t.Fatalf("renewal not acknowledged: %s %s %v", yi, dst, o)
	}

	// A request carrying another client's hardware address is ignored.
	send(any4, dhcpMessage(dhcpDiscover, macB, any4))
	if len(tb.a.take()) != 0 {
		t.Fatal("answered DHCP for a foreign chaddr")
	}
}

func testConfig(t *testing.T, conf string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	if err := (pki.Dir{Path: dir}).Init("server", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	c, err := config.ParseString(conf + "\nca " + filepath.Join(dir, "ca.crt") +
		"\ncert " + filepath.Join(dir, "server.crt") + "\nkey " + filepath.Join(dir, "server.key") + "\n")
	if err != nil {
		t.Fatal(err)
	}
	return Load(c)
}

func TestTAPConfig(t *testing.T) {
	cfg, err := testConfig(t, "dev tap\nserver-bridge 10.9.0.4 255.255.255.0 10.9.0.128 10.9.0.130")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TAP || cfg.Gateway.String() != "10.9.0.4" || cfg.Subnet.String() != "10.9.0.0/24" ||
		cfg.PoolStart.String() != "10.9.0.128" || cfg.PoolEnd.String() != "10.9.0.130" || cfg.DHCP ||
		cfg.MAC.String() != "02:00:0a:09:00:04" {
		t.Fatalf("bad config %+v", cfg)
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		ip, err := s.pool.alloc("", netip.Addr{}, false)
		if err != nil {
			break
		}
		got = append(got, ip.String())
	}
	if len(got) != 3 || got[0] != "10.9.0.128" || got[2] != "10.9.0.130" {
		t.Fatalf("pool handed out %v", got)
	}

	cfg, err = testConfig(t, "dev tap0\nserver 10.9.0.0 255.255.255.0\nlladdr 02:11:22:33:44:55")
	if err != nil || !cfg.TAP || cfg.Gateway.String() != "10.9.0.1" || cfg.PoolStart.IsValid() || cfg.MAC.String() != "02:11:22:33:44:55" {
		t.Fatalf("server with dev tap: %v %+v", err, cfg)
	}
	cfg, err = testConfig(t, "dev vpn\ndev-type tap\nserver-bridge\nserver 10.10.0.0/24")
	if err != nil || !cfg.TAP || !cfg.DHCP || cfg.NoGateway || cfg.Gateway.String() != "10.10.0.1" {
		t.Fatalf("DHCP mode: %v %+v", err, cfg)
	}
	cfg, err = testConfig(t, "dev tap\nserver-bridge nogw")
	if err != nil || !cfg.DHCP || !cfg.NoGateway || cfg.Subnet.String() != "10.8.0.0/24" {
		t.Fatalf("nogw: %v %+v", err, cfg)
	}
	cfg, err = testConfig(t, "dev tun\nserver 10.8.0.0 255.255.255.0")
	if err != nil || cfg.TAP {
		t.Fatalf("tun: %v %+v", err, cfg)
	}

	for _, bad := range []string{
		"dev tun\nserver-bridge 10.9.0.1 255.255.255.0 10.9.0.100 10.9.0.200",
		"dev tun\nlladdr 02:00:00:00:00:01",
		"dev tap\nlladdr 01:00:00:00:00:01",
		"dev tap\nserver-bridge 10.9.0.1 255.255.255.0 10.9.1.100 10.9.1.200",
		"dev tap\nserver-bridge 10.9.0.1 255.255.255.0 10.9.0.200 10.9.0.100",
		"dev tap\nserver-bridge 10.9.0.1 255.255.255.0 10.9.0.100 10.9.0.255",
		"dev tap\nserver-bridge 10.9.0.0 255.255.255.0 10.9.0.100 10.9.0.200",
		"dev tap\nserver-bridge 10.9.0.1 255.255.255.0",
		"dev tap\nserver 10.9.0.0 255.255.255.0\nserver-bridge 10.9.0.1 255.255.255.0 10.9.0.100 10.9.0.200",
		"dev foo",
	} {
		if _, err := testConfig(t, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
