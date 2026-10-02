package server

import (
	"net"
	"net/netip"

	"github.com/softvpn/softvpn/internal/config"
)

// loadBridge reads the TAP-mode directives:
//
//	server-bridge GATEWAY NETMASK POOL_START POOL_END
//	server-bridge [nogw]   DHCP: clients get their address by DHCP; the
//	                       range comes from "server" (default 10.8.0.0/24)
//	lladdr MAC             the gateway's Ethernet address
//
// "server NETWORK NETMASK" with dev tap works as in tun mode.
func (cfg *Config) loadBridge(c *config.Config) error {
	d, bridged := c.Last("server-bridge")
	l, hasMAC := c.Last("lladdr")
	if !cfg.TAP {
		if bridged {
			return d.Errorf("server-bridge requires dev tap")
		}
		if hasMAC {
			return l.Errorf("lladdr requires dev tap")
		}
		return nil
	}
	if bridged {
		switch {
		case len(d.Args) == 0:
			cfg.DHCP = true
		case len(d.Args) == 1 && d.Args[0] == "nogw":
			cfg.DHCP, cfg.NoGateway = true, true
		case len(d.Args) == 4:
			if c.Has("server") {
				return d.Errorf("cannot be combined with \"server\"")
			}
			var a [4]netip.Addr
			for i, s := range d.Args {
				ip, err := netip.ParseAddr(s)
				if err != nil || !ip.Is4() {
					return d.Errorf("invalid IPv4 address %q", s)
				}
				a[i] = ip
			}
			ones, bits := net.IPMask(a[1].AsSlice()).Size()
			if bits != 32 || ones > 29 {
				return d.Errorf("invalid netmask %q (need /29 or larger)", d.Args[1])
			}
			subnet := netip.PrefixFrom(a[0], ones).Masked()
			gw, start, end := a[0], a[2], a[3]
			bcast := lastAddr(subnet)
			if gw == subnet.Addr() || gw == bcast {
				return d.Errorf("%s is not a usable gateway address in %s", gw, subnet)
			}
			if !subnet.Contains(start) || !subnet.Contains(end) || end.Less(start) ||
				start == subnet.Addr() || end == bcast {
				return d.Errorf("pool %s-%s is not a range of host addresses in %s", start, end, subnet)
			}
			cfg.Subnet, cfg.Gateway, cfg.PoolStart, cfg.PoolEnd = subnet, gw, start, end
		default:
			return d.Errorf("expects GATEWAY NETMASK POOL_START POOL_END, nogw, or no arguments (DHCP)")
		}
	}

	if hasMAC {
		hw, err := net.ParseMAC(l.Arg(0))
		if err != nil || len(hw) != 6 || hw[0]&1 != 0 || macOf(hw) == (mac{}) {
			return l.Errorf("invalid unicast Ethernet address %q", l.Arg(0))
		}
		cfg.MAC = hw
	} else {
		// Locally administered, derived from the gateway address so it is
		// stable across restarts.
		gw := cfg.Gateway.As4()
		cfg.MAC = net.HardwareAddr{0x02, 0x00, gw[0], gw[1], gw[2], gw[3]}
	}
	return nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= ^uint32(0) >> p.Bits()
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// newBridge creates the virtual switch for TAP mode.
func (s *Server) newBridge() *bridge {
	return newBridge(bridgeOptions{
		MAC:            s.cfg.MAC,
		Gateway:        s.cfg.Gateway,
		Subnet:         s.cfg.Subnet,
		ClientToClient: s.cfg.ClientToClient,
		DHCPRouter:     !s.cfg.NoGateway,
		Local:          s.routeBridged,
		Log:            s.log,
	})
}

// routeBridged is the gateway's port on the virtual switch: it receives the
// IPv4 packets that TAP clients send to the gateway's MAC address. It routes
// like Packet does in tun mode, except that the subnet itself is on-link:
// clients reach each other through the switch, not through the gateway.
func (s *Server) routeBridged(pkt []byte) {
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	switch {
	case dst == s.cfg.Gateway:
		s.stack.Inject(pkt)
	case s.cfg.Subnet.Contains(dst), dst.IsMulticast(), dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
	case pkt[9] == protoICMP:
		if h, ok := parseIP(pkt); ok {
			if _, ok := s.policy("icmp", netip.AddrPort{}, netip.AddrPortFrom(dst, 0)); ok {
				s.pinger.forward(h, pkt)
			}
		}
	default:
		s.stack.Inject(pkt)
	}
}
