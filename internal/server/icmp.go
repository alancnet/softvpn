package server

import (
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// pinger NATs ICMP and ICMPv6 echo requests using unprivileged ping sockets
// (SOCK_DGRAM/IPPROTO_ICMP and IPPROTO_ICMPV6). These need no capability,
// only a gid within net.ipv4.ping_group_range (which covers both families),
// and Docker opens it to every group by default. Each (client, destination,
// echo id) flow gets its own socket; the kernel rewrites the echo id, and
// replies are mapped back to the client's id.
type pinger struct {
	log     *slog.Logger
	deliver func([]byte)

	mu       sync.Mutex
	flows    map[pingKey]*pingFlow
	disabled [2]atomic.Bool // per family: [0] IPv4, [1] IPv6
}

type pingKey struct {
	client, dst netip.Addr
	id          uint16
}

type pingFlow struct {
	conn *icmp.PacketConn
	last atomic.Int64
}

const pingIdle = 30 * time.Second

func newPinger(log *slog.Logger, deliver func([]byte)) *pinger {
	return &pinger{log: log, deliver: deliver, flows: map[pingKey]*pingFlow{}}
}

// forward sends the echo request pkt (with parsed header h) on its way.
func (p *pinger) forward(h ipHeader, pkt []byte) {
	v6 := h.dst.Is6()
	fam, network, laddr, typ := 0, "udp4", "0.0.0.0", byte(icmpEchoRequest)
	var echo icmp.Type = ipv4.ICMPTypeEcho
	if v6 {
		fam, network, laddr, typ = 1, "udp6", "::", icmpv6EchoRequest
		echo = ipv6.ICMPTypeEchoRequest
	}
	if p.disabled[fam].Load() {
		return
	}
	icmpData := pkt[h.payload:]
	if len(icmpData) < 8 || icmpData[0] != typ || icmpData[1] != 0 {
		return // only echo requests are forwarded
	}
	key := pingKey{client: h.src, dst: h.dst, id: binary.BigEndian.Uint16(icmpData[4:])}
	seq := binary.BigEndian.Uint16(icmpData[6:])
	data := icmpData[8:]

	p.mu.Lock()
	f := p.flows[key]
	if f == nil {
		conn, err := icmp.ListenPacket(network, laddr)
		if err != nil {
			p.mu.Unlock()
			p.log.Warn("ICMP forwarding unavailable (unprivileged ping sockets not permitted; check net.ipv4.ping_group_range)", "family", network, "err", err)
			p.disabled[fam].Store(true)
			return
		}
		f = &pingFlow{conn: conn}
		p.flows[key] = f
		go p.readReplies(key, f)
	}
	p.mu.Unlock()
	f.last.Store(time.Now().UnixNano())

	// The kernel fills in the checksum (for ICMPv6 it needs the pseudo
	// header, which only it knows the source address for).
	msg := icmp.Message{Type: echo, Body: &icmp.Echo{ID: int(key.id), Seq: int(seq), Data: data}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	if _, err := f.conn.WriteTo(b, &net.UDPAddr{IP: key.dst.AsSlice()}); err != nil {
		p.log.Debug("icmp: send failed", "dst", key.dst, "err", err)
	}
}

func (p *pinger) readReplies(key pingKey, f *pingFlow) {
	defer func() {
		p.mu.Lock()
		delete(p.flows, key)
		p.mu.Unlock()
		f.conn.Close()
	}()
	buf := make([]byte, 65535)
	for {
		f.conn.SetReadDeadline(time.Now().Add(pingIdle))
		n, _, err := f.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() &&
				time.Since(time.Unix(0, f.last.Load())) < pingIdle {
				continue
			}
			return
		}
		proto, want := protoICMP, icmp.Type(ipv4.ICMPTypeEchoReply)
		if key.dst.Is6() {
			proto, want = protoICMPv6, ipv6.ICMPTypeEchoReply
		}
		m, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || m.Type != want {
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		reply := icmp.Message{Type: want, Body: &icmp.Echo{ID: int(key.id), Seq: echo.Seq, Data: echo.Data}}
		if key.dst.Is6() {
			body, err := reply.Marshal(icmp.IPv6PseudoHeader(key.dst.AsSlice(), key.client.AsSlice()))
			if err == nil {
				p.deliver(ipv6Packet(key.dst, key.client, protoICMPv6, body))
			}
			continue
		}
		body, err := reply.Marshal(nil)
		if err != nil {
			continue
		}
		p.deliver(ipv4Packet(key.dst, key.client, protoICMP, body))
	}
}

// ipv4Packet wraps payload in a minimal IPv4 header.
func ipv4Packet(src, dst netip.Addr, proto byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64 // TTL
	b[9] = proto
	s4, d4 := src.As4(), dst.As4()
	copy(b[12:16], s4[:])
	copy(b[16:20], d4[:])
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))
	copy(b[20:], payload)
	return b
}

// ipv6Packet wraps payload in a minimal IPv6 header.
func ipv6Packet(src, dst netip.Addr, proto byte, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6] = proto
	b[7] = 64 // hop limit
	s16, d16 := src.As16(), dst.As16()
	copy(b[8:24], s16[:])
	copy(b[24:40], d16[:])
	copy(b[40:], payload)
	return b
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
