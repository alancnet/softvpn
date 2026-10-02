package ovpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
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
	for _, cipher := range append(append([]string(nil), SupportedCiphers...), CBCCiphers...) {
		srv, err := newDataKeys(cipher, "SHA256", block)
		if err != nil {
			t.Fatal(err)
		}
		// A "client" is the same key block with the directions swapped.
		swapped := append(append([]byte(nil), block[keySize:]...), block[:keySize]...)
		cli, _ := newDataKeys(cipher, "SHA256", swapped)

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
			if len(hdr) == 4 && !isCBC(cipher) { // the peer id is authenticated in V2
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
	if c, push := negotiateCipher([]string{"CHACHA20-POLY1305", "AES-256-GCM"}, pi, "", ""); c != "CHACHA20-POLY1305" || !push {
		t.Fatalf("server preference not honoured: %s", c)
	}
	if c, _ := negotiateCipher([]string{"AES-128-GCM"}, pi, "", ""); c != "" {
		t.Fatal("negotiated a cipher the client does not offer")
	}
	if c, _ := negotiateCipher(SupportedCiphers, peerInfo{"IV_NCP": "2"}, "", ""); c != "AES-256-GCM" {
		t.Fatalf("IV_NCP=2 fallback: %s", c)
	}
	// OpenVPN 2.4 with "cipher AES-256-CBC": its OCC cipher is negotiable.
	if c, push := negotiateCipher([]string{"AES-256-GCM", "AES-256-CBC"}, peerInfo{"IV_NCP": "2"}, "AES-256-CBC", ""); c != "AES-256-GCM" || !push {
		t.Fatalf("2.4 client: %s", c)
	}
	// No negotiation at all (2.3, or --ncp-disable): the OCC cipher if the
	// server allows it, else the fallback. Neither is pushed.
	if c, push := negotiateCipher([]string{"AES-256-GCM", "BF-CBC"}, peerInfo{}, "BF-CBC", "AES-128-CBC"); c != "BF-CBC" || push {
		t.Fatalf("poor man's NCP: %s %v", c, push)
	}
	if c, push := negotiateCipher(SupportedCiphers, peerInfo{}, "AES-128-CBC", "aes-128-cbc"); c != "AES-128-CBC" || push {
		t.Fatalf("data-ciphers-fallback: %s %v", c, push)
	}
	if c, _ := negotiateCipher([]string{"AES-128-GCM"}, pi, "", "AES-128-CBC"); c != "" {
		t.Fatalf("the fallback is only for clients that cannot negotiate, got %s", c)
	}
	if c, _ := negotiateCipher(SupportedCiphers, peerInfo{}, "BF-CBC", ""); c != "" {
		t.Fatalf("no fallback configured, got %s", c)
	}
	if v, ok := occOption("V4,dev-type tun,comp-lzo,cipher BF-CBC,auth SHA1", "cipher"); v != "BF-CBC" || !ok {
		t.Fatal("occOption cipher")
	}
	if _, ok := occOption("V4,dev-type tun,comp-lzo,cipher BF-CBC", "comp-lzo"); !ok {
		t.Fatal("occOption flag")
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

// TestCBCFormat builds a packet the way OpenVPN's openvpn_encrypt_v1 does,
// independently of sealCBC, and checks both directions.
func TestCBCFormat(t *testing.T) {
	block := make([]byte, keyBlockSize)
	for i := range block {
		block[i] = byte(i * 7)
	}
	c2s := block[:keySize]
	d, err := newDataKeys("AES-128-CBC", "SHA1", block)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("an ip packet, 32 bytes long.....")
	plain := append([]byte{0, 0, 0, 1}, payload...)
	plain = append(plain, bytes.Repeat([]byte{12}, 12)...) // PKCS#7 to 48 bytes
	iv := bytes.Repeat([]byte{0xaa}, 16)
	b, _ := aes.NewCipher(c2s[:16])
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(ct, plain)
	mac := hmac.New(sha1.New, c2s[64:64+20])
	mac.Write(iv)
	mac.Write(ct)
	pkt := append([]byte{opDataV1 << 3}, mac.Sum(nil)...)
	pkt = append(append(pkt, iv...), ct...)
	got, err := d.open(pkt, 1)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("open: %q %v", got, err)
	}

	// sealCBC output: hdr | HMAC-SHA1 (20) | IV (16) | 48 bytes ciphertext.
	out := d.seal([]byte{opDataV2 << 3, 0, 0, 9}, payload)
	if len(out) != 4+20+16+48 {
		t.Fatalf("sealed %d bytes", len(out))
	}
	s2c := block[keySize:]
	mac = hmac.New(sha1.New, s2c[64:64+20])
	mac.Write(out[24:])
	if !bytes.Equal(mac.Sum(nil), out[4:24]) {
		t.Fatal("HMAC must cover IV and ciphertext only")
	}
	b, _ = aes.NewCipher(s2c[:16])
	pt := make([]byte, 48)
	cipher.NewCBCDecrypter(b, out[24:40]).CryptBlocks(pt, out[40:])
	if binary.BigEndian.Uint32(pt) != 1 || !bytes.Equal(pt[4:36], payload) || pt[47] != 12 {
		t.Fatalf("plaintext layout %x", pt)
	}
	for name := range Digests {
		if _, err := newDataKeys("BF-CBC", name, block); err != nil {
			t.Fatal(name, err)
		}
	}
	if _, err := newDataKeys("AES-256-CBC", "none", block); err == nil {
		t.Fatal("CBC without HMAC accepted")
	}
}

func TestSetCompression(t *testing.T) {
	v26 := peerInfo{"IV_VER": "2.6.20", "IV_COMP_STUB": "1", "IV_COMP_STUBv2": "1"}
	cases := []struct {
		name       string
		pi         peerInfo
		clientComp bool
		a          Assignment
		mode       Compress
		push       string
	}{
		{"no compression anywhere", v26, false, Assignment{}, CompressUnset, ""},
		{"migrate a 2.6 client", v26, true, Assignment{}, CompressStubV2, "compress stub-v2"},
		{"migrate a 2.3 client", peerInfo{}, true, Assignment{}, CompressLZOStub, "comp-lzo no"},
		{"server setting is pushed", v26, false, Assignment{Compress: CompressLZ4V2}, CompressLZ4V2, "compress lz4-v2"},
		{"2.3 only knows comp-lzo", peerInfo{}, true, Assignment{Compress: CompressLZ4V2}, CompressLZOStub, "comp-lzo no"},
		{"2.3 with comp-lzo", peerInfo{}, true, Assignment{Compress: CompressLZO}, CompressLZO, "comp-lzo yes"},
		{"pushed by the admin", v26, true, Assignment{Push: []string{"compress lz4"}}, CompressLZ4, ""},
	}
	for _, c := range cases {
		s := &Session{srv: &Server{opt: Options{AllowCompression: AllowCompressionYes}}, pi: c.pi, clientComp: c.clientComp}
		s.setCompression(&c.a)
		if s.comp.mode != c.mode || s.compPush != c.push || s.comp.allow != AllowCompressionYes {
			t.Errorf("%s: got %v %q", c.name, s.comp.mode, s.compPush)
		}
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
