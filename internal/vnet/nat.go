package vnet

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/softvpn/softvpn/internal/relay"
)

// Policy decides what to do with a new flow from a VPN client. It returns
// the host-network address to connect to (usually dst itself), or ok=false
// to reject the flow.
type Policy func(network string, src, dst netip.AddrPort) (target string, ok bool)

// NATOptions configures EnableNAT.
type NATOptions struct {
	Gateway     netip.Prefix // the server's own virtual address and subnet
	Policy      Policy
	Log         *slog.Logger
	DialTimeout time.Duration
	UDPIdle     time.Duration
}

// EnableNAT turns the stack into a software NAT router.
//
// The NIC is put in promiscuous mode so the stack accepts packets for any
// destination, and in spoofing mode so it can reply from any source. Every
// new TCP connection (SYN) and UDP flow is intercepted by a forwarder, which
// opens an ordinary socket on the host - so traffic leaves through the
// host's default route with the host's address, exactly like masquerading,
// but without iptables, a TUN device, or any capability.
//
// TCP connections are only accepted after the outbound dial succeeds, so a
// client sees "connection refused" or a timeout just as it would on a real
// network.
func (st *Stack) EnableNAT(o NATOptions) error {
	if o.DialTimeout == 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.UDPIdle == 0 {
		o.UDPIdle = 60 * time.Second
	}
	if err := st.SetAddress(o.Gateway); err != nil {
		return err
	}
	if err := st.s.SetPromiscuousMode(nicID, true); err != nil {
		return fmt.Errorf("promiscuous mode: %s", err)
	}
	if err := st.s.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("spoofing: %s", err)
	}

	tcpFwd := tcp.NewForwarder(st.s, 0, 4096, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		src := netip.AddrPortFrom(fromTCPIP(id.RemoteAddress), id.RemotePort)
		dst := netip.AddrPortFrom(fromTCPIP(id.LocalAddress), id.LocalPort)
		target, ok := o.Policy("tcp", src, dst)
		if !ok {
			o.Log.Debug("nat: tcp rejected by policy", "src", src, "dst", dst)
			r.Complete(true)
			return
		}
		out, err := net.DialTimeout("tcp", target, o.DialTimeout)
		if err != nil {
			o.Log.Debug("nat: tcp dial failed", "src", src, "dst", dst, "err", err)
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			out.Close()
			r.Complete(true)
			return
		}
		r.Complete(false)
		ep.SocketOptions().SetKeepAlive(true)
		o.Log.Debug("nat: tcp open", "src", src, "dst", dst, "via", out.LocalAddr())
		relay.Stream(gonet.NewTCPConn(&wq, ep), out)
		o.Log.Debug("nat: tcp closed", "src", src, "dst", dst)
	})
	st.s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(st.s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		src := netip.AddrPortFrom(fromTCPIP(id.RemoteAddress), id.RemotePort)
		dst := netip.AddrPortFrom(fromTCPIP(id.LocalAddress), id.LocalPort)
		target, ok := o.Policy("udp", src, dst)
		if !ok {
			o.Log.Debug("nat: udp rejected by policy", "src", src, "dst", dst)
			return
		}
		// The endpoint must be created synchronously: it takes over the
		// packet that triggered this request.
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return
		}
		in := gonet.NewUDPConn(st.s, &wq, ep)
		go func() {
			out, err := net.Dial("udp", target)
			if err != nil {
				o.Log.Debug("nat: udp dial failed", "src", src, "dst", dst, "err", err)
				in.Close()
				return
			}
			o.Log.Debug("nat: udp open", "src", src, "dst", dst, "via", out.LocalAddr())
			relay.Datagram(in, out, o.UDPIdle)
		}()
	})
	st.s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return nil
}
