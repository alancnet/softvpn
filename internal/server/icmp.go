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
)

// pinger NATs ICMP echo requests using unprivileged ICMP sockets
// (SOCK_DGRAM/IPPROTO_ICMP). These need no capability, only a gid within
// net.ipv4.ping_group_range, which Docker opens to every group by default.
// Each (client, destination, echo id) flow gets its own socket; the kernel
// rewrites the echo id, and replies are mapped back to the client's id.
type pinger struct {
	log     *slog.Logger
	deliver func([]byte)

	mu       sync.Mutex
	flows    map[pingKey]*pingFlow
	disabled atomic.Bool
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

func (p *pinger) forward(pkt []byte) {
	if p.disabled.Load() {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+8 || pkt[ihl] != byte(ipv4.ICMPTypeEcho) || pkt[ihl+1] != 0 {
		return // only echo requests are forwarded
	}
	key := pingKey{
		client: netip.AddrFrom4([4]byte(pkt[12:16])),
		dst:    netip.AddrFrom4([4]byte(pkt[16:20])),
		id:     binary.BigEndian.Uint16(pkt[ihl+4:]),
	}
	seq := binary.BigEndian.Uint16(pkt[ihl+6:])
	data := pkt[ihl+8:]

	p.mu.Lock()
	f := p.flows[key]
	if f == nil {
		conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			p.mu.Unlock()
			p.log.Warn("ICMP forwarding unavailable (unprivileged ping sockets not permitted; check net.ipv4.ping_group_range)", "err", err)
			p.disabled.Store(true)
			return
		}
		f = &pingFlow{conn: conn}
		p.flows[key] = f
		go p.readReplies(key, f)
	}
	p.mu.Unlock()
	f.last.Store(time.Now().UnixNano())

	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: int(key.id), Seq: int(seq), Data: data}}
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
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		reply := icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: int(key.id), Seq: echo.Seq, Data: echo.Data}}
		body, err := reply.Marshal(nil)
		if err != nil {
			continue
		}
		p.deliver(ipv4Packet(key.dst, key.client, 1, body))
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
