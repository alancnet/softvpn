package ovpn

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"time"
)

// testdata/*.key were made by OpenVPN 2.6.20:
//
//	openvpn --genkey secret ta.key
//	openvpn --genkey tls-crypt-v2-server tls-crypt-v2-server.key
//	openvpn --tls-crypt-v2 tls-crypt-v2-server.key --genkey tls-crypt-v2-client tls-crypt-v2-client.key
//	openvpn --tls-crypt-v2 tls-crypt-v2-server.key --genkey tls-crypt-v2-client tls-crypt-v2-client-metadata.key aGVsbG8=
func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStaticKeyFormat(t *testing.T) {
	ref := readTestdata(t, "ta.key")
	k, err := ParseStaticKey(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.Marshal(), ref) {
		t.Fatalf("Marshal differs from openvpn's output:\n%s", k.Marshal())
	}
	if k[0] != 0x4d || k[255] != 0x2e {
		t.Fatal("key bytes out of order")
	}
	g := GenerateStaticKey()
	if back, err := ParseStaticKey(g.Marshal()); err != nil || *back != *g {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := ParseStaticKey(bytes.Replace(ref, []byte("626df55a0281b4dc4594394c12c2212e\n"), nil, 1)); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestTLSCryptV2KeyFormats(t *testing.T) {
	ref := readTestdata(t, "tls-crypt-v2-server.key")
	srv, err := ParseTLSCryptV2ServerKey(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(srv.Marshal(), ref) {
		t.Fatalf("server key Marshal differs from openvpn's:\n%s", srv.Marshal())
	}

	for _, c := range []struct {
		file     string
		metadata []byte
	}{
		{"tls-crypt-v2-client.key", nil},
		{"tls-crypt-v2-client-metadata.key", append([]byte{MetadataUser}, "hello"...)},
	} {
		ck, wkc, err := ParseTLSCryptV2ClientKey(readTestdata(t, c.file))
		if err != nil {
			t.Fatal(c.file, err)
		}
		got, md, err := srv.UnwrapClientKey(wkc)
		if err != nil {
			t.Fatalf("%s: openvpn's wrapped key does not unwrap: %v", c.file, err)
		}
		if *got != *ck {
			t.Fatalf("%s: unwrapped key differs from the client's copy", c.file)
		}
		if c.metadata == nil {
			if len(md) != 9 || md[0] != MetadataTimestamp {
				t.Fatalf("%s: want timestamp metadata, got %x", c.file, md)
			}
			ts := time.Unix(int64(binary.BigEndian.Uint64(md[1:])), 0)
			if ts.Year() < 2024 {
				t.Fatalf("implausible timestamp %v", ts)
			}
		} else if !bytes.Equal(md, c.metadata) {
			t.Fatalf("%s: metadata %q", c.file, md)
		}
		// Wrapping is deterministic (SIV), so re-wrapping must reproduce
		// openvpn's bytes exactly.
		again, err := srv.WrapClientKey(ck, md)
		if err != nil || !bytes.Equal(again, wkc) {
			t.Fatalf("%s: WrapClientKey differs from openvpn's WKc", c.file)
		}
		wkc[40] ^= 1
		if _, _, err := srv.UnwrapClientKey(wkc); err != errWKc {
			t.Fatalf("tampered WKc: %v", err)
		}
	}

	file, err := srv.NewTLSCryptV2ClientKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ck, wkc, err := ParseTLSCryptV2ClientKey(file)
	if err != nil {
		t.Fatal(err)
	}
	if got, md, err := srv.UnwrapClientKey(wkc); err != nil || *got != *ck || md[0] != MetadataTimestamp {
		t.Fatalf("generated client key: %v", err)
	}
	if _, _, err := GenerateTLSCryptV2ServerKey().UnwrapClientKey(wkc); err != errWKc {
		t.Fatal("client key accepted by another server key")
	}
	if _, err := srv.WrapClientKey(ck, make([]byte, maxMetadata+1)); err == nil {
		t.Fatal("oversized metadata accepted")
	}
}

func testControlPacket(op byte) []byte {
	p := controlPacket{op: op, sid: sessionID{1, 2, 3, 4, 5, 6, 7, 8}, acks: []uint32{3},
		ackedSID: sessionID{8, 7, 6, 5, 4, 3, 2, 1}, messageID: 4, payload: []byte("tls record")}
	return p.marshal()
}

// checkWrap sends packets both ways between a client and server wrap and
// checks authentication, layout and replay protection.
func checkWrap(t *testing.T, cli, srv *tlsWrap, overhead int) {
	t.Helper()
	plain := testControlPacket(opControlV1)
	wire := cli.wrap(plain)
	if len(wire) != len(plain)+overhead || !bytes.Equal(wire[:9], plain[:9]) {
		t.Fatalf("wire layout: %d bytes (want %d), header %x", len(wire), len(plain)+overhead, wire[:9])
	}
	got, err := srv.unwrap(wire)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := srv.unwrap(wire); err != errWrapReplay {
		t.Fatalf("replay: %v", err)
	}
	for _, i := range []int{0, 5, 12, len(wire) - 1} {
		bad := append([]byte(nil), cli.wrap(plain)...)
		bad[i] ^= 1
		if _, err := srv.unwrap(bad); err != errWrapAuth {
			t.Fatalf("tampered byte %d: %v", i, err)
		}
	}
	if _, err := srv.unwrap(cli.wrap(plain)); err != nil {
		t.Fatalf("later packet: %v", err)
	}
	reply := srv.wrap(plain)
	if got, err := cli.unwrap(reply); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("server to client: %v", err)
	}
	if _, err := srv.unwrap(srv.wrap(plain)); err == nil {
		t.Fatal("server accepted its own packet: directions are not separated")
	}
}

func TestTLSAuth(t *testing.T) {
	k := GenerateStaticKey()
	for _, c := range []struct {
		digest   string
		srv, cli int
		size     int
	}{
		{"", KeyDirNormal, KeyDirInverse, 20},
		{"SHA256", KeyDirNormal, KeyDirInverse, 32},
		{"sha512", KeyDirInverse, KeyDirNormal, 64},
	} {
		srv, err := newTLSWrap(&ControlWrap{Mode: WrapTLSAuth, Key: k, Direction: c.srv, Digest: c.digest})
		if err != nil {
			t.Fatal(err)
		}
		cli, _ := newTLSWrap(&ControlWrap{Mode: WrapTLSAuth, Key: k, Direction: c.cli, Digest: c.digest})
		checkWrap(t, cli, srv, c.size+pidSize)
	}

	// Without a direction both sides use the same key; the packet-id window
	// still rejects replays.
	bidi, _ := newTLSWrap(&ControlWrap{Mode: WrapTLSAuth, Key: k, Direction: KeyDirBidi})
	peer, _ := newTLSWrap(&ControlWrap{Mode: WrapTLSAuth, Key: k, Direction: KeyDirBidi})
	if _, err := bidi.unwrap(peer.wrap(testControlPacket(opAckV1))); err != nil {
		t.Fatal(err)
	}
	if _, err := DigestFunc("MD4"); err == nil {
		t.Fatal("unsupported digest accepted")
	}
}

func TestTLSCrypt(t *testing.T) {
	k := GenerateStaticKey()
	srv, _ := newTLSWrap(&ControlWrap{Mode: WrapTLSCrypt, Key: k})
	cli := newTLSCrypt(k, WrapTLSCrypt, KeyDirInverse)
	checkWrap(t, cli, srv, pidSize+32)
	wire := cli.wrap(testControlPacket(opControlV1))
	if bytes.Contains(wire, []byte("tls record")) {
		t.Fatal("tls-crypt payload is not encrypted")
	}
}

func TestPacketIDTime(t *testing.T) {
	w := &tlsWrap{}
	for _, c := range []struct {
		id, time uint32
		want     bool
	}{{1, 100, true}, {2, 100, true}, {1, 100, false}, {1, 99, false}, {1, 101, true}, {2, 100, false}} {
		if got := w.acceptPID(c.id, c.time); got != c.want {
			t.Fatalf("acceptPID(%d, %d) = %v", c.id, c.time, got)
		}
	}
}

func TestTLSCryptV2Reset(t *testing.T) {
	srvKey := GenerateTLSCryptV2ServerKey()
	ck := GenerateStaticKey()
	wkc, _ := srvKey.WrapClientKey(ck, TimestampMetadata(time.Now()))
	cfg := &ControlWrap{Mode: WrapTLSCryptV2, V2Key: srvKey}
	cli := newTLSCrypt(ck, WrapTLSCryptV2, KeyDirInverse)

	reset := testControlPacket(opControlHardResetClientV3)
	w, plain, err := acceptReset(cfg, append(cli.wrap(reset), wkc...))
	if err != nil || !bytes.Equal(plain, reset) {
		t.Fatalf("acceptReset: %v", err)
	}
	// A retransmitted reset and a P_CONTROL_WKC_V1 also carry the WKc.
	if got, err := w.unwrapInput(append(cli.wrap(reset), wkc...)); err != nil || !bytes.Equal(got, reset) {
		t.Fatalf("retransmitted reset: %v", err)
	}
	got, err := w.unwrapInput(append(cli.wrap(testControlPacket(opControlWKCV1)), wkc...))
	if err != nil || opcodeOf(got[0]) != opControlV1 {
		t.Fatalf("P_CONTROL_WKC_V1: %v", err)
	}
	if _, err := w.unwrapInput(cli.wrap(testControlPacket(opControlV1))); err != nil {
		t.Fatalf("P_CONTROL_V1: %v", err)
	}
	if got, err := cli.unwrap(w.wrap(testControlPacket(opControlHardResetServerV2))); err != nil || opcodeOf(got[0]) != opControlHardResetServerV2 {
		t.Fatalf("server reply: %v", err)
	}

	// Wrong server key, a V2 reset in V3 mode, and V3 without tls-crypt-v2.
	other := &ControlWrap{Mode: WrapTLSCryptV2, V2Key: GenerateTLSCryptV2ServerKey()}
	if _, _, err := acceptReset(other, append(cli.wrap(reset), wkc...)); err == nil {
		t.Fatal("reset accepted under another server key")
	}
	if _, _, err := acceptReset(cfg, cli.wrap(testControlPacket(opControlHardResetClientV2))); err == nil {
		t.Fatal("V2 reset accepted in tls-crypt-v2 mode")
	}
	if _, _, err := acceptReset(nil, append(cli.wrap(reset), wkc...)); err == nil {
		t.Fatal("V3 reset accepted without tls-crypt-v2")
	}
	if _, _, err := acceptReset(&ControlWrap{Mode: WrapTLSCrypt, Key: ck}, testControlPacket(opControlHardResetClientV2)); err == nil {
		t.Fatal("unwrapped reset accepted in tls-crypt mode")
	}
	if _, p, err := acceptReset(nil, testControlPacket(opControlHardResetClientV2)); err != nil || opcodeOf(p[0]) != opControlHardResetClientV2 {
		t.Fatal("plain reset without wrapping")
	}
}
