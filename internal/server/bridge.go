package server

import (
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
)

// TAP (bridged) mode: the data channel carries Ethernet frames, and the
// server is a virtual Ethernet switch. Each client session is one switch
// port; the server itself is another port with its own MAC address, which
// answers ARP for the gateway address and hands IPv4 packets to the same
// router as tun mode (gVisor stack, soft NAT, ICMP NAT, DNS relay).
//
// The gVisor NIC stays IP-only: the gateway port does ARP and Ethernet
// framing here. gVisor's own ARP cannot be used with the NAT, because the
// NIC spoofs source addresses and gVisor refuses to resolve a neighbour on
// behalf of a source address it does not own (ErrBadLocalAddress), so
// replies from NATed flows would never leave. The switch already knows each
// client's MAC and address, so no resolution is needed at all.

const (
	etherHdrLen = 14
	etherIPv4   = 0x0800
	etherARP    = 0x0806
	arpLen      = 28
)

type mac [6]byte

func (m mac) String() string    { return net.HardwareAddr(m[:]).String() }
func (m mac) isGroup() bool     { return m[0]&1 != 0 } // multicast, including broadcast
func (m mac) isZero() bool      { return m == mac{} }
func macOf(b []byte) (m mac)    { copy(m[:], b); return m }
func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b[:4])) }

var broadcastMAC = mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// switchPort is a client attached to the switch; *ovpn.Session is one.
type switchPort interface {
	SendPacket(frame []byte)
	CommonName() string
}

// bridgePort is the switch's view of a client. A port is bound to the
// address the server assigned and to the first MAC address it sends from;
// frames from any other source are dropped (anti-spoofing).
type bridgePort struct {
	p   switchPort
	ip  netip.Addr
	mac mac // zero until learned; never changes afterwards

	// DHCP options, from the client's pushed dhcp-option lines.
	dns    []netip.Addr
	domain string
}

type bridgeOptions struct {
	MAC            net.HardwareAddr
	Gateway        netip.Addr
	Subnet         netip.Prefix
	ClientToClient bool
	DHCPRouter     bool             // offer the gateway as router in DHCP
	Local          func(pkt []byte) // IPv4 packets for the gateway port
	Log            *slog.Logger
}

type bridge struct {
	o     bridgeOptions
	gwMAC mac

	mu    sync.RWMutex
	ports map[switchPort]*bridgePort
	byMAC map[mac]*bridgePort
	byIP  map[netip.Addr]*bridgePort
}

func newBridge(o bridgeOptions) *bridge {
	return &bridge{
		o:     o,
		gwMAC: macOf(o.MAC),
		ports: map[switchPort]*bridgePort{},
		byMAC: map[mac]*bridgePort{},
		byIP:  map[netip.Addr]*bridgePort{},
	}
}

// attach adds a client port bound to ip. push is the client's push list,
// which supplies DNS servers and domain for DHCP.
func (b *bridge) attach(p switchPort, ip netip.Addr, push []string) {
	bp := &bridgePort{p: p, ip: ip}
	bp.dns, bp.domain = dhcpOptions(push)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ports[p] = bp
	b.byIP[ip] = bp
}

func (b *bridge) detach(p switchPort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	bp := b.ports[p]
	if bp == nil {
		return
	}
	delete(b.ports, p)
	if b.byIP[bp.ip] == bp {
		delete(b.byIP, bp.ip)
	}
	if b.byMAC[bp.mac] == bp {
		delete(b.byMAC, bp.mac)
	}
}

// learn returns p's port if src is its MAC address, learning it from the
// first frame. It returns nil for a frame the port may not send.
func (b *bridge) learn(p switchPort, src mac) *bridgePort {
	if src.isGroup() || src.isZero() || src == b.gwMAC {
		return nil
	}
	b.mu.RLock()
	bp := b.ports[p]
	learned := bp != nil && !bp.mac.isZero()
	b.mu.RUnlock()
	if bp == nil {
		return nil
	}
	if learned {
		if bp.mac != src {
			b.o.Log.Debug("bridge: dropping frame from foreign MAC", "client", p.CommonName(), "src", src, "learned", bp.mac)
			return nil
		}
		return bp
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if !bp.mac.isZero() { // learned meanwhile
		if bp.mac != src {
			return nil
		}
		return bp
	}
	if other := b.byMAC[src]; other != nil {
		b.o.Log.Debug("bridge: MAC already in use by another client", "client", p.CommonName(), "src", src, "owner", other.p.CommonName())
		return nil
	}
	bp.mac = src
	b.byMAC[src] = bp
	b.o.Log.Info("bridge: learned client MAC", "client", p.CommonName(), "mac", src, "ip", bp.ip)
	return bp
}

// input is an Ethernet frame from a client. The switch owns the slice.
func (b *bridge) input(p switchPort, f []byte) {
	if len(f) < etherHdrLen {
		return
	}
	dst, src := macOf(f[0:6]), macOf(f[6:12])
	bp := b.learn(p, src)
	if bp == nil {
		return
	}
	payload := f[etherHdrLen:]
	switch binary.BigEndian.Uint16(f[12:14]) {
	case etherARP:
		if !b.inputARP(bp, payload) {
			return
		}
		if dst == b.gwMAC {
			return // only ever an answer to an ARP request the gateway did not send
		}
	case etherIPv4:
		pkt, ok := ipv4Payload(payload)
		if !ok {
			return
		}
		if isDHCPToServer(pkt) {
			b.dhcp(bp, pkt)
			return
		}
		if addr4(pkt[12:16]) != bp.ip {
			b.o.Log.Debug("bridge: dropping packet with spoofed source", "client", p.CommonName(), "src", addr4(pkt[12:16]), "assigned", bp.ip)
			return
		}
		if isDHCPFromServer(pkt) {
			return // a client must not act as a DHCP server for the others
		}
		if dst == b.gwMAC {
			b.o.Local(pkt)
			return
		}
	default:
		// IPv6, VLAN tags and other protocols are not bridged.
		return
	}

	if !b.o.ClientToClient {
		return // without client-to-client, clients only reach the server
	}
	b.mu.RLock()
	var to []switchPort
	if peer := b.byMAC[dst]; peer != nil && !dst.isGroup() {
		to = append(to, peer.p)
	} else {
		// Broadcast, multicast and unknown unicast are flooded.
		for q := range b.ports {
			if q != p {
				to = append(to, q)
			}
		}
	}
	b.mu.RUnlock()
	for _, q := range to {
		q.SendPacket(f)
	}
}

// inputARP validates an ARP packet against the port's MAC and address and
// answers requests for the gateway. It reports whether the packet may be
// forwarded to other clients.
func (b *bridge) inputARP(bp *bridgePort, a []byte) bool {
	if len(a) < arpLen || binary.BigEndian.Uint16(a[0:2]) != 1 || binary.BigEndian.Uint16(a[2:4]) != etherIPv4 ||
		a[4] != 6 || a[5] != 4 {
		return false
	}
	op := binary.BigEndian.Uint16(a[6:8])
	sha, spa, tpa := macOf(a[8:14]), addr4(a[14:18]), addr4(a[24:28])
	// RFC 5227 probes (requests from 0.0.0.0) are allowed.
	if sha != bp.mac || spa != bp.ip && !(op == 1 && spa.IsUnspecified()) {
		b.o.Log.Debug("bridge: dropping spoofed ARP", "client", bp.p.CommonName(), "sha", sha, "spa", spa)
		return false
	}
	if tpa != b.o.Gateway {
		return op == 1 || op == 2
	}
	if op == 1 {
		r := make([]byte, etherHdrLen+arpLen)
		copy(r[0:6], sha[:])
		copy(r[6:12], b.gwMAC[:])
		binary.BigEndian.PutUint16(r[12:], etherARP)
		ra := r[etherHdrLen:]
		copy(ra, a[:6]) // htype, ptype, hlen, plen
		binary.BigEndian.PutUint16(ra[6:], 2)
		copy(ra[8:14], b.gwMAC[:])
		gw := b.o.Gateway.As4()
		copy(ra[14:18], gw[:])
		copy(ra[18:24], sha[:])
		copy(ra[24:28], a[14:18])
		bp.p.SendPacket(r)
	}
	return false
}

// output sends an IPv4 packet from the gateway port (the stack, the ICMP
// NAT) to the client that owns its destination address.
func (b *bridge) output(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	b.mu.RLock()
	bp := b.byIP[addr4(pkt[16:20])]
	var to mac
	if bp != nil {
		to = bp.mac
	}
	b.mu.RUnlock()
	if to.isZero() {
		return // unknown, or the client has not sent anything yet
	}
	b.send(bp, to, pkt)
}

func (b *bridge) send(bp *bridgePort, to mac, pkt []byte) {
	f := make([]byte, etherHdrLen+len(pkt))
	copy(f[0:6], to[:])
	copy(f[6:12], b.gwMAC[:])
	binary.BigEndian.PutUint16(f[12:], etherIPv4)
	copy(f[etherHdrLen:], pkt)
	bp.p.SendPacket(f)
}

// ipv4Payload validates an IPv4 header and trims Ethernet padding.
func ipv4Payload(b []byte) ([]byte, bool) {
	if len(b) < 20 || b[0]>>4 != 4 || int(b[0]&0x0f)*4 < 20 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < int(b[0]&0x0f)*4 || n > len(b) {
		return nil, false
	}
	return b[:n], true
}

// udpPorts returns the ports of an unfragmented UDP packet.
func udpPorts(pkt []byte) (src, dst uint16, ok bool) {
	ihl := int(pkt[0]&0x0f) * 4
	if pkt[9] != 17 || len(pkt) < ihl+8 || binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(pkt[ihl:]), binary.BigEndian.Uint16(pkt[ihl+2:]), true
}

func isDHCPToServer(pkt []byte) bool {
	_, dst, ok := udpPorts(pkt)
	return ok && dst == 67
}

func isDHCPFromServer(pkt []byte) bool {
	src, _, ok := udpPorts(pkt)
	return ok && src == 67
}
