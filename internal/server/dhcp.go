package server

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"time"
)

// A minimal DHCP server on the virtual switch (RFC 2131). It never hands
// out addresses of its own: a client is always offered the address the
// server assigned to its session, so DHCP works for clients configured with
// "server-bridge" (no arguments, "route-gateway dhcp") and also for clients
// that run a DHCP client on a tap interface that already got "ifconfig".

const (
	dhcpLease = time.Hour

	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpNak      = 6
	dhcpInform   = 8

	optMask      = 1
	optRouter    = 3
	optDNS       = 6
	optDomain    = 15
	optReqIP     = 50
	optLease     = 51
	optMsgType   = 53
	optServerID  = 54
	optRenewal   = 58
	optRebinding = 59
	optEnd       = 255
)

var dhcpMagic = []byte{99, 130, 83, 99}

// dhcpOptions extracts the DNS servers and domain from pushed
// "dhcp-option DNS x" and "dhcp-option DOMAIN x" lines.
func dhcpOptions(push []string) (dns []netip.Addr, domain string) {
	for _, p := range push {
		f := strings.Fields(p)
		if len(f) != 3 || f[0] != "dhcp-option" {
			continue
		}
		switch strings.ToUpper(f[1]) {
		case "DNS":
			if a, err := netip.ParseAddr(f[2]); err == nil && a.Is4() {
				dns = append(dns, a)
			}
		case "DOMAIN":
			domain = f[2]
		}
	}
	return dns, domain
}

// dhcp answers a DHCP message (a UDP packet to port 67) from a client.
func (b *bridge) dhcp(bp *bridgePort, pkt []byte) {
	if src := addr4(pkt[12:16]); src != bp.ip && !src.IsUnspecified() {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	m := pkt[ihl+8:]
	if len(m) < 240 || m[0] != 1 || m[1] != 1 || m[2] != 6 || string(m[236:240]) != string(dhcpMagic) ||
		macOf(m[28:34]) != bp.mac {
		return
	}
	opts := parseDHCPOptions(m[240:])
	if len(opts[optMsgType]) != 1 {
		return
	}
	ciaddr := addr4(m[12:16])
	var reply byte
	switch opts[optMsgType][0] {
	case dhcpDiscover:
		reply = dhcpOffer
	case dhcpRequest:
		want := ciaddr
		if r := opts[optReqIP]; len(r) == 4 {
			want = addr4(r)
		}
		if id := opts[optServerID]; len(id) == 4 && addr4(id) != b.o.Gateway {
			return // the client chose another server
		}
		reply = dhcpAck
		if want != bp.ip {
			reply = dhcpNak
		}
	case dhcpInform:
		reply = dhcpAck
	default:
		return // release, decline
	}

	r := make([]byte, 240, 300)
	r[0], r[1], r[2] = 2, 1, 6
	copy(r[4:8], m[4:8])     // xid
	copy(r[10:12], m[10:12]) // flags
	copy(r[12:16], m[12:16]) // ciaddr
	if reply != dhcpNak && opts[optMsgType][0] != dhcpInform {
		ip := bp.ip.As4()
		copy(r[16:20], ip[:]) // yiaddr
	}
	copy(r[28:44], m[28:44]) // chaddr
	copy(r[236:], dhcpMagic)
	gw := b.o.Gateway.As4()
	r = append(r, optMsgType, 1, reply, optServerID, 4)
	r = append(r, gw[:]...)
	if reply != dhcpNak {
		mask := net.CIDRMask(b.o.Subnet.Bits(), 32)
		r = append(r, optMask, 4)
		r = append(r, mask...)
		if b.o.DHCPRouter {
			r = append(r, optRouter, 4)
			r = append(r, gw[:]...)
		}
		if len(bp.dns) > 0 {
			r = append(r, optDNS, byte(4*len(bp.dns)))
			for _, d := range bp.dns {
				a := d.As4()
				r = append(r, a[:]...)
			}
		}
		if d := bp.domain; d != "" && len(d) < 256 {
			r = append(r, optDomain, byte(len(d)))
			r = append(r, d...)
		}
		if opts[optMsgType][0] != dhcpInform {
			secs := uint32(dhcpLease / time.Second)
			r = append(r, optLease, 4)
			r = binary.BigEndian.AppendUint32(r, secs)
			r = append(r, optRenewal, 4)
			r = binary.BigEndian.AppendUint32(r, secs/2)
			r = append(r, optRebinding, 4)
			r = binary.BigEndian.AppendUint32(r, secs*7/8)
		}
	}
	r = append(r, optEnd)
	for len(r) < 300 { // BOOTP minimum
		r = append(r, 0)
	}

	// RFC 2131 4.1: unicast to a configured client, otherwise broadcast
	// when asked to or for a NAK, otherwise to the offered address. The
	// Ethernet destination is always the client's MAC.
	dst := netip.AddrFrom4([4]byte{255, 255, 255, 255})
	switch {
	case !ciaddr.IsUnspecified() && reply != dhcpNak:
		dst = ciaddr
	case m[10]&0x80 != 0 || reply == dhcpNak:
	default:
		dst = bp.ip
	}
	b.send(bp, bp.mac, ipv4Packet(b.o.Gateway, dst, 17, udpDatagram(b.o.Gateway, dst, 67, 68, r)))
}

// parseDHCPOptions returns the options of a DHCP message by code.
func parseDHCPOptions(b []byte) map[byte][]byte {
	opts := map[byte][]byte{}
	for len(b) > 0 {
		code := b[0]
		if code == optEnd {
			break
		}
		if code == 0 { // pad
			b = b[1:]
			continue
		}
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			break
		}
		opts[code] = b[2 : 2+int(b[1])]
		b = b[2+int(b[1]):]
	}
	return opts
}

// udpDatagram builds a UDP header and payload with its checksum.
func udpDatagram(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload)
	s4, d4 := src.As4(), dst.As4()
	pseudo := make([]byte, 0, 12+len(u))
	pseudo = append(pseudo, s4[:]...)
	pseudo = append(pseudo, d4[:]...)
	pseudo = append(pseudo, 0, 17)
	pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(u)))
	pseudo = append(pseudo, u...)
	c := checksum(pseudo)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], c)
	return u
}
