package ovpn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestControlPacketRoundTrip(t *testing.T) {
	in := controlPacket{op: opControlV1, keyID: 3, sid: sessionID{1, 2, 3, 4, 5, 6, 7, 8},
		acks: []uint32{7, 9}, ackedSID: sessionID{9, 9, 9, 9, 9, 9, 9, 9}, messageID: 42, payload: []byte("tls bytes")}
	out, err := parseControl(in.marshal())
	if err != nil {
		t.Fatal(err)
	}
	if out.op != in.op || out.keyID != in.keyID || out.sid != in.sid || out.ackedSID != in.ackedSID ||
		out.messageID != in.messageID || !bytes.Equal(out.payload, in.payload) || len(out.acks) != 2 || out.acks[1] != 9 {
		t.Fatalf("round trip mismatch: %+v", out)
	}

	ack := controlPacket{op: opAckV1, sid: in.sid, acks: []uint32{1}, ackedSID: in.ackedSID}
	b := ack.marshal()
	if len(b) != 1+8+1+4+8 {
		t.Fatalf("ACK_V1 must not carry a message id, got %d bytes", len(b))
	}
	if _, err := parseControl(b[:12]); err == nil {
		t.Fatal("truncated packet parsed")
	}
}

func TestReliableInOrderDeliveryAndAcks(t *testing.T) {
	r := newReliable(0, true)
	if got := r.receive(1, opControlV1, []byte("b")); len(got) != 0 {
		t.Fatal("out-of-order message delivered early")
	}
	got := r.receive(0, opControlV1, []byte("a"))
	if len(got) != 2 || string(got[0].payload) != "a" || string(got[1].payload) != "b" {
		t.Fatalf("got %v", got)
	}
	if got := r.receive(0, opControlV1, []byte("a")); len(got) != 0 {
		t.Fatal("duplicate delivered twice")
	}
	if r.receive(100, opControlV1, nil) != nil || len(r.pendingAcks) != 3 {
		t.Fatalf("far-future message must be dropped unacked; acks=%v", r.pendingAcks)
	}
	pkts := r.collect(time.Now(), sessionID{1}, sessionID{2})
	if len(pkts) != 1 {
		t.Fatalf("want one ACK packet, got %d", len(pkts))
	}
	p, _ := parseControl(pkts[0])
	if p.op != opAckV1 || len(p.acks) != 3 || p.ackedSID != (sessionID{2}) {
		t.Fatalf("bad ack packet %+v", p)
	}
}

func TestReliableRetransmitAndWindow(t *testing.T) {
	r := newReliable(1, true)
	r.enqueue(opControlV1, make([]byte, maxControlPayload*(sendWindow+2)))
	now := time.Now()
	if n := len(r.collect(now, sessionID{}, sessionID{})); n != sendWindow {
		t.Fatalf("sent %d packets, window is %d", n, sendWindow)
	}
	if n := len(r.collect(now, sessionID{}, sessionID{})); n != 0 {
		t.Fatal("retransmitted before timeout")
	}
	if n := len(r.collect(now.Add(initialRTO+time.Millisecond), sessionID{}, sessionID{})); n != sendWindow {
		t.Fatalf("expected %d retransmissions, got %d", sendWindow, n)
	}
	r.ack([]uint32{0, 1})
	if n := len(r.collect(now.Add(initialRTO+2*time.Millisecond), sessionID{}, sessionID{})); n != 2 {
		t.Fatalf("acking 2 should open the window for 2 new packets, got %d", n)
	}

	tcp := newReliable(0, false)
	tcp.enqueue(opControlV1, []byte("x"))
	tcp.collect(now, sessionID{}, sessionID{})
	if n := len(tcp.collect(now.Add(time.Minute), sessionID{}, sessionID{})); n != 0 {
		t.Fatal("TCP mode must not retransmit")
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	for _, c := range []struct {
		pid  uint32
		want bool
	}{{0, false}, {1, true}, {1, false}, {5, true}, {3, true}, {3, false}, {200, true}, {100, false}, {199, true}} {
		if got := w.accept(c.pid); got != c.want {
			t.Fatalf("accept(%d) = %v, want %v", c.pid, got, c.want)
		}
	}
}

func TestDataSealOpen(t *testing.T) {
	block := make([]byte, keyBlockSize)
	for i := range block {
		block[i] = byte(i)
	}
	for _, cipher := range SupportedCiphers {
		srv, err := newDataKeys(cipher, block)
		if err != nil {
			t.Fatal(err)
		}
		// A "client" is the same key block with the directions swapped.
		swapped := append(append([]byte(nil), block[keySize:]...), block[:keySize]...)
		cli, _ := newDataKeys(cipher, swapped)

		for _, hdr := range [][]byte{{opDataV2<<3 | 1, 0, 0, 7}, {opDataV1<<3 | 1}} {
			pkt := srv.seal(hdr, []byte("ip packet"))
			if !bytes.HasPrefix(pkt, hdr) {
				t.Fatal("header not preserved")
			}
			pt, err := cli.open(pkt, len(hdr))
			if err != nil || string(pt) != "ip packet" {
				t.Fatalf("%s: open: %q %v", cipher, pt, err)
			}
			if _, err := cli.open(pkt, len(hdr)); err == nil {
				t.Fatal("replay accepted")
			}
			pkt = srv.seal(hdr, []byte("ip packet"))
			pkt[len(pkt)-1] ^= 1
			if _, err := cli.open(pkt, len(hdr)); err != errAuth {
				t.Fatalf("tampered packet: %v", err)
			}
			if len(hdr) == 4 { // the peer id is authenticated in V2
				pkt = srv.seal(hdr, []byte("x"))
				pkt[3] ^= 1
				if _, err := cli.open(pkt, 4); err != errAuth {
					t.Fatal("peer id not covered by AEAD")
				}
			}
		}
	}
}

func TestTLS1PRF(t *testing.T) {
	// Deterministic, and the two halves of the secret must both matter.
	a := tls1PRF([]byte("secret-secret"), []byte("seed"), 100)
	if len(a) != 100 || !bytes.Equal(a, tls1PRF([]byte("secret-secret"), []byte("seed"), 100)) {
		t.Fatal("PRF not deterministic")
	}
	if bytes.Equal(a, tls1PRF([]byte("secret-secreT"), []byte("seed"), 100)) ||
		bytes.Equal(a, tls1PRF([]byte("Secret-secret"), []byte("seed"), 100)) {
		t.Fatal("PRF ignores part of the secret")
	}
	if !bytes.Equal(a[:40], tls1PRF([]byte("secret-secret"), []byte("seed"), 40)) {
		t.Fatal("PRF output not a stream")
	}
}

func TestKeyMethod2(t *testing.T) {
	msg := make([]byte, 5, 300)
	msg[4] = 2
	msg = append(msg, bytes.Repeat([]byte{1}, 48+32+32)...)
	msg = appendString(msg, "V4,dev-type tun,tls-client")
	base := len(msg)
	msg = appendString(msg, "")
	msg = appendString(msg, "")
	msg = appendString(msg, "IV_VER=2.6.20\nIV_PROTO=990\nIV_CIPHERS=AES-256-GCM:CHACHA20-POLY1305\n")

	km, err := parseClientKeyMethod2(msg)
	if err != nil {
		t.Fatal(err)
	}
	if km.options != "V4,dev-type tun,tls-client" || !strings.Contains(km.peerInfo, "IV_VER=2.6.20") {
		t.Fatalf("parsed %+v", km)
	}
	if _, err := parseClientKeyMethod2(msg[:base]); err != nil {
		t.Fatalf("optional fields must be optional: %v", err)
	}
	if _, err := parseClientKeyMethod2(msg[:base+3]); err != errIncomplete {
		t.Fatalf("partial field: %v", err)
	}

	pi := parsePeerInfo(km.peerInfo)
	if pi.protoFlags()&ivProtoTLSKeyExport == 0 || pi.protoFlags()&ivProtoDataV2 == 0 {
		t.Fatal("IV_PROTO flags")
	}
	if c, _ := negotiateCipher([]string{"CHACHA20-POLY1305", "AES-256-GCM"}, pi); c != "CHACHA20-POLY1305" {
		t.Fatalf("server preference not honoured: %s", c)
	}
	if _, ok := negotiateCipher([]string{"AES-128-GCM"}, pi); ok {
		t.Fatal("negotiated a cipher the client does not offer")
	}
	if c, _ := negotiateCipher(SupportedCiphers, peerInfo{"IV_NCP": "2"}); c != "AES-256-GCM" {
		t.Fatalf("IV_NCP=2 fallback: %s", c)
	}

	srv := serverKeyMethod2(make([]byte, 32), make([]byte, 32), "V4,tls-server")
	if binary.BigEndian.Uint32(srv) != 0 || srv[4] != 2 || len(srv) != 5+64+2+14+2+2+2 {
		t.Fatalf("server key method layout: %d bytes", len(srv))
	}
}

func TestPushReplyContinuation(t *testing.T) {
	s := &Session{srv: &Server{opt: Options{PushPing: 10 * time.Second, PushPingRestart: 60 * time.Second}}, cipher: "AES-256-GCM", pi: peerInfo{}}
	a := &Assignment{Netmask: "255.255.255.0"}
	for i := 0; i < 60; i++ {
		a.Push = append(a.Push, "route 192.168.100.0 255.255.255.0")
	}
	msgs := s.pushReply(a)
	if len(msgs) < 2 {
		t.Fatal("long push list was not split")
	}
	for i, m := range msgs {
		if !strings.HasPrefix(m, "PUSH_REPLY,") || len(m) > 1000 {
			t.Fatalf("message %d malformed (%d bytes)", i, len(m))
		}
		want := ",push-continuation 2"
		if i == len(msgs)-1 {
			want = ",push-continuation 1"
		}
		if !strings.HasSuffix(m, want) {
			t.Fatalf("message %d missing %q", i, want)
		}
	}
	if got := strings.Count(strings.Join(msgs, ""), "route 192.168.100.0"); got != 60 {
		t.Fatalf("lost options: %d", got)
	}
}

func TestPushReplyIPv6(t *testing.T) {
	s := &Session{srv: &Server{opt: Options{PushPing: 10 * time.Second, PushPingRestart: 60 * time.Second}}, cipher: "AES-256-GCM", pi: peerInfo{}}
	a := &Assignment{
		IP: netip.MustParseAddr("10.8.0.2"), Netmask: "255.255.255.0", Gateway: netip.MustParseAddr("10.8.0.1"),
		IP6: netip.MustParsePrefix("fd00:8::1000/64"), Gateway6: netip.MustParseAddr("fd00:8::1"),
	}
	msgs := s.pushReply(a)
	if len(msgs) != 1 || !strings.Contains(msgs[0], ",ifconfig-ipv6 fd00:8::1000/64 fd00:8::1,") ||
		!strings.Contains(msgs[0], ",ifconfig 10.8.0.2 255.255.255.0") {
		t.Fatalf("push reply: %q", msgs)
	}
	a.IP6 = netip.Prefix{}
	if msgs := s.pushReply(a); strings.Contains(msgs[0], "ifconfig-ipv6") {
		t.Fatalf("ifconfig-ipv6 pushed without an IPv6 address: %q", msgs)
	}
}
