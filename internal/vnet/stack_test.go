package vnet

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	client6  = netip.MustParseAddr("fd00:8::1000")
	gateway6 = netip.MustParseAddr("fd00:8::1")
)

// newTestStack starts a NAT stack with an IPv6 gateway; its output arrives
// on the returned channel.
func newTestStack(t *testing.T, policy Policy) (*Stack, chan []byte) {
	t.Helper()
	out := make(chan []byte, 64)
	st, err := New(1500, func(p []byte) { out <- p })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	err = st.EnableNAT(NATOptions{
		Gateway:  netip.MustParsePrefix("10.8.0.1/24"),
		Gateway6: netip.PrefixFrom(gateway6, 64),
		Policy:   policy,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, out
}

func ip6(src, dst netip.Addr, proto byte, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6], b[7] = proto, 64
	s, d := src.As16(), dst.As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	copy(b[40:], payload)
	return b
}

// await returns the first IPv6 packet from the stack matching ok.
func await(t *testing.T, out chan []byte, ok func(h header.IPv6) bool) header.IPv6 {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case p := <-out:
			if len(p) >= header.IPv6MinimumSize && p[0]>>4 == 6 && ok(header.IPv6(p)) {
				return header.IPv6(p)
			}
		case <-timeout:
			t.Fatal("no matching packet from the stack")
		}
	}
}

// The stack answers ping6 for the gateway address itself (no NDP or DAD in
// the way on this point-to-point link).
func TestGatewayAnswersPing6(t *testing.T) {
	st, out := newTestStack(t, func(string, netip.AddrPort, netip.AddrPort) (string, bool) { return "", false })
	msg := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: 7, Seq: 1, Data: []byte("ping6")}}
	body, err := msg.Marshal(icmp.IPv6PseudoHeader(client6.AsSlice(), gateway6.AsSlice()))
	if err != nil {
		t.Fatal(err)
	}
	st.Inject(ip6(client6, gateway6, 58, body))

	h := await(t, out, func(h header.IPv6) bool { return h.NextHeader() == 58 })
	if src, dst := fromTCPIP(h.SourceAddress()), fromTCPIP(h.DestinationAddress()); src != gateway6 || dst != client6 {
		t.Fatalf("reply %s -> %s", src, dst)
	}
	m, err := icmp.ParseMessage(58, h.Payload())
	if err != nil || m.Type != ipv6.ICMPTypeEchoReply {
		t.Fatalf("not an echo reply: %v %v", m, err)
	}
	if e := m.Body.(*icmp.Echo); e.ID != 7 || string(e.Data) != "ping6" {
		t.Fatalf("echo reply %+v", e)
	}
}

// A TCP connection to an arbitrary IPv6 address is terminated by the stack
// (answering from that spoofed address) and re-opened as a host socket.
func TestNATTCPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	remote := netip.MustParseAddrPort("[2001:db8::5]:80")
	seen := make(chan netip.AddrPort, 1)
	st, out := newTestStack(t, func(network string, src, dst netip.AddrPort) (string, bool) {
		seen <- dst
		return ln.Addr().String(), true
	})

	syn := make([]byte, header.TCPMinimumSize)
	tcp := header.TCP(syn)
	tcp.Encode(&header.TCPFields{SrcPort: 40000, DstPort: remote.Port(), SeqNum: 1000,
		DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagSyn, WindowSize: 65535})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, toTCPIP(client6), toTCPIP(remote.Addr()), uint16(len(syn)))
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	st.Inject(ip6(client6, remote.Addr(), 6, syn))

	if dst := <-seen; dst != remote {
		t.Fatalf("policy saw %s", dst)
	}
	h := await(t, out, func(h header.IPv6) bool { return h.NextHeader() == 6 })
	reply := header.TCP(h.Payload())
	if fromTCPIP(h.SourceAddress()) != remote.Addr() || reply.Flags() != header.TCPFlagSyn|header.TCPFlagAck || reply.AckNumber() != 1001 {
		t.Fatalf("expected SYN-ACK from %s, got %s flags %s", remote, fromTCPIP(h.SourceAddress()), reply.Flags())
	}
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("NAT did not open the host connection: %v", err)
	}
	c.Close()
}
