package server

import (
	"net/netip"
	"sort"

	"github.com/softvpn/softvpn/internal/ovpn"
)

// routes is the virtual router's table: which client an address belongs
// to. A client's own addresses are host routes, looked up in a map; the
// networks behind clients (iroute, iroute-ipv6) are matched longest prefix
// first. Both families share one table.
type routes struct {
	hosts map[netip.Addr]*ovpn.Session
	nets  []route // longest prefix first
}

type route struct {
	prefix netip.Prefix
	ss     *ovpn.Session
}

func newRoutes() *routes { return &routes{hosts: map[netip.Addr]*ovpn.Session{}} }

// add points p at ss and returns the session that previously owned exactly
// p, if any: like OpenVPN, the client that connected last wins.
func (r *routes) add(p netip.Prefix, ss *ovpn.Session) (prev *ovpn.Session) {
	p = p.Masked()
	if p.IsSingleIP() {
		prev = r.hosts[p.Addr()]
		r.hosts[p.Addr()] = ss
		return prev
	}
	for i := range r.nets {
		if r.nets[i].prefix == p {
			prev, r.nets[i].ss = r.nets[i].ss, ss
			return prev
		}
	}
	r.nets = append(r.nets, route{p, ss})
	sort.SliceStable(r.nets, func(i, j int) bool { return r.nets[i].prefix.Bits() > r.nets[j].prefix.Bits() })
	return nil
}

// remove deletes p if ss still owns it.
func (r *routes) remove(p netip.Prefix, ss *ovpn.Session) {
	p = p.Masked()
	if p.IsSingleIP() {
		if r.hosts[p.Addr()] == ss {
			delete(r.hosts, p.Addr())
		}
		return
	}
	for i := range r.nets {
		if r.nets[i].prefix == p && r.nets[i].ss == ss {
			r.nets = append(r.nets[:i], r.nets[i+1:]...)
			return
		}
	}
}

// lookup returns the client that a matches, or nil.
func (r *routes) lookup(a netip.Addr) *ovpn.Session {
	if ss := r.hosts[a]; ss != nil {
		return ss
	}
	for _, n := range r.nets {
		if n.prefix.Contains(a) {
			return n.ss
		}
	}
	return nil
}

// ipHeader is what the router needs from an IPv4 or IPv6 packet.
type ipHeader struct {
	src, dst netip.Addr
	proto    byte // transport protocol; for IPv6, after extension headers
	payload  int  // offset of the transport header
}

// IPv6 extension headers that share the generic "next header, length"
// layout and may precede the transport header.
const (
	ipv6HopByHop = 0
	ipv6Routing  = 43
	ipv6DestOpts = 60
)

// parseIP parses the network header of a tunnel packet.
func parseIP(pkt []byte) (h ipHeader, ok bool) {
	if len(pkt) < 1 {
		return h, false
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < 20 || ihl < 20 || len(pkt) < ihl {
			return h, false
		}
		h.src = netip.AddrFrom4([4]byte(pkt[12:16]))
		h.dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		h.proto, h.payload = pkt[9], ihl
		return h, true
	case 6:
		if len(pkt) < 40 {
			return h, false
		}
		h.src = netip.AddrFrom16([16]byte(pkt[8:24]))
		h.dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		h.proto, h.payload = pkt[6], 40
		for h.proto == ipv6HopByHop || h.proto == ipv6Routing || h.proto == ipv6DestOpts {
			if len(pkt) < h.payload+2 {
				return h, false
			}
			h.proto, h.payload = pkt[h.payload], h.payload+(int(pkt[h.payload+1])+1)*8
		}
		return h, len(pkt) >= h.payload
	}
	return h, false
}

const (
	protoICMP   = 1
	protoICMPv6 = 58

	icmpEchoRequest   = 8
	icmpv6EchoRequest = 128
)

// isEcho6 reports whether pkt is an ICMPv6 echo request.
func (h ipHeader) isEcho6(pkt []byte) bool {
	return h.dst.Is6() && h.proto == protoICMPv6 && len(pkt) >= h.payload+8 && pkt[h.payload] == icmpv6EchoRequest
}
