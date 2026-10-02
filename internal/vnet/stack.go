// Package vnet wraps gVisor's userspace TCP/IP stack. A Stack has a single
// virtual NIC whose "wire" is a pair of Go functions: packets the stack emits
// are handed to an output callback, and packets from VPN clients are
// injected with Inject. No TUN device, raw socket or capability is involved.
package vnet

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID tcpip.NICID = 1

// Stack is a userspace IPv4 network stack with one virtual interface.
type Stack struct {
	s      *stack.Stack
	ep     *channel.Endpoint
	cancel context.CancelFunc

	mu   sync.Mutex
	addr netip.Prefix
}

// New creates a stack whose outbound packets are passed to out. out is
// called from a single goroutine and owns the slice it receives.
func New(mtu int, out func(pkt []byte)) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		// HandleLocal must stay off: in promiscuous mode every source address
		// would look local and gVisor would drop all inbound packets.
		HandleLocal: false,
	})

	// Tune TCP for a high bandwidth-delay tunnel rather than gVisor's
	// conservative defaults.
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate)
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: 1 << 20, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: 1 << 20, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)

	ep := channel.New(1024, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{s: s, ep: ep, cancel: cancel}
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt.IsNil() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			v := pkt.ToView() // caller-owned copy
			pkt.DecRef()
			out(v.AsSlice())
		}
	}()
	return st, nil
}

// Close tears down the stack and every connection on it.
func (st *Stack) Close() {
	st.cancel()
	st.ep.Close()
	st.s.Close()
}

// Inject delivers an IPv4 packet received from the tunnel to the stack.
func (st *Stack) Inject(pkt []byte) {
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	st.ep.InjectInbound(ipv4.ProtocolNumber, pb)
	pb.DecRef()
}

// SetAddress assigns the interface address, replacing any previous one.
func (st *Stack) SetAddress(p netip.Prefix) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.addr == p {
		return nil
	}
	if st.addr.IsValid() {
		st.s.RemoveAddress(nicID, toTCPIP(st.addr.Addr()))
	}
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   toTCPIP(p.Addr()),
			PrefixLen: p.Bits(),
		},
	}
	if err := st.s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("add address %s: %s", p, err)
	}
	st.addr = p
	return nil
}

func toTCPIP(a netip.Addr) tcpip.Address { return tcpip.AddrFrom4(a.Unmap().As4()) }

func fromTCPIP(a tcpip.Address) netip.Addr {
	if a.Len() == 4 {
		return netip.AddrFrom4(a.As4())
	}
	addr, _ := netip.AddrFromSlice(a.AsSlice())
	return addr
}
