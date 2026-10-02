package ovpn

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// testdata/lz_vectors.txt holds payloads compressed by the reference
// liblzo2 (lzo1x_1_15_compress, as OpenVPN calls it) and liblz4
// (LZ4_compress_default), one "name hex" per line.
func loadVectors(t *testing.T) map[string][]byte {
	b, err := os.ReadFile("testdata/lz_vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	v := map[string][]byte{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		name, h, _ := strings.Cut(line, " ")
		if v[name], err = hex.DecodeString(h); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func TestReferenceVectors(t *testing.T) {
	v := loadVectors(t)
	for _, i := range []string{"0", "1", "2"} {
		plain := v["plain"+i]
		got, err := lzo1xDecompress(v["lzo"+i], maxDecompressed)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("lzo%s: %v (got %d bytes, want %d)", i, err, len(got), len(plain))
		}
		got, err = lz4Decompress(v["lz4"+i], maxDecompressed)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("lz4%s: %v (got %d bytes, want %d)", i, err, len(got), len(plain))
		}
		// Output limits and truncation must fail cleanly, never panic.
		if _, err := lz4Decompress(v["lz4"+i], len(plain)-1); err == nil {
			t.Errorf("lz4%s: output limit not enforced", i)
		}
		if _, err := lzo1xDecompress(v["lzo"+i], len(plain)-1); err == nil {
			t.Errorf("lzo%s: output limit not enforced", i)
		}
		for n := 0; n < len(v["lzo"+i]); n += 7 {
			lzo1xDecompress(v["lzo"+i][:n], maxDecompressed)
			lz4Decompress(v["lz4"+i][:min(n, len(v["lz4"+i]))], maxDecompressed)
		}
	}
}

func TestLZ4RoundTrip(t *testing.T) {
	v := loadVectors(t)
	inputs := [][]byte{v["plain0"], v["plain1"], v["plain2"], bytes.Repeat([]byte("ab"), 40000)}
	for i, in := range inputs {
		z := lz4Compress(in)
		if z == nil || len(z) >= len(in) {
			t.Fatalf("input %d: not compressed", i)
		}
		out, err := lz4Decompress(z, len(in))
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("input %d: round trip failed: %v", i, err)
		}
	}
	if lz4Compress(randomBytes(1400)) != nil {
		t.Fatal("random data should not compress")
	}
}

func TestCompressionFraming(t *testing.T) {
	ip := append([]byte{0x45, 0, 0, 0x54}, bytes.Repeat([]byte{0}, 200)...)
	cases := []struct {
		mode Compress
		wire []byte // framing of "\x45abc" (uncompressed)
	}{
		{CompressUnset, []byte("\x45abc")},
		{CompressStub, []byte("\xfbabc\x45")},
		{CompressLZ4, []byte("\xfbabc\x45")},
		{CompressStubV2, []byte("\x45abc")},
		{CompressLZ4V2, []byte("\x45abc")},
		{CompressLZO, []byte("\xfa\x45abc")},
		{CompressLZOStub, []byte("\xfa\x45abc")},
	}
	for _, c := range cases {
		for _, allow := range []AllowCompression{AllowCompressionNo, AllowCompressionAsym, AllowCompressionYes} {
			cp := compressor{c.mode, allow}
			if allow != AllowCompressionYes {
				if got := cp.frame([]byte("\x45abc")); !bytes.Equal(got, c.wire) {
					t.Errorf("%v: frame = %x, want %x", c.mode, got, c.wire)
				}
				if got, err := cp.unframe(append([]byte(nil), c.wire...)); err != nil || string(got) != "\x45abc" {
					t.Errorf("%v: unframe(%x) = %x, %v", c.mode, c.wire, got, err)
				}
			}
			for _, p := range [][]byte{ip, []byte("\x50escaped"), {0x45}, {}} {
				w := cp.frame(append([]byte(nil), p...))
				compressed := len(w) < len(p)
				if compressed != (allow == AllowCompressionYes && !c.mode.Stub() && c.mode != CompressLZO && len(p) >= compressThreshold) {
					t.Errorf("%v allow=%d: compressed=%v for %d bytes", c.mode, allow, compressed, len(p))
				}
				got, err := cp.unframe(w)
				if err != nil || !bytes.Equal(got, p) {
					t.Errorf("%v: round trip of %x: %x, %v", c.mode, p, got, err)
				}
			}
		}
	}
	// V2 escapes payloads that start with the indicator byte.
	if got := (compressor{CompressStubV2, 0}).frame([]byte("\x50x")); string(got) != "\x50\x00\x50x" {
		t.Errorf("stub-v2 escape: %x", got)
	}
	// Bad headers are rejected.
	for _, c := range []struct {
		mode Compress
		wire string
	}{{CompressLZO, "\x69abc"}, {CompressLZ4, "\xfaabc"}, {CompressStubV2, "\x50\x07abc"}, {CompressStubV2, "\x50"}} {
		if _, err := (compressor{c.mode, 0}).unframe([]byte(c.wire)); err == nil {
			t.Errorf("%v: accepted %x", c.mode, c.wire)
		}
	}
}

func TestDecompressRealPayloads(t *testing.T) {
	v := loadVectors(t)
	plain := v["plain0"]
	lz4 := append([]byte(nil), v["lz40"]...)
	swapped := append(append([]byte{lz4CompressByte}, lz4[1:]...), lz4[0])
	cases := []struct {
		mode Compress
		wire []byte
	}{
		{CompressLZO, append([]byte{lzoCompressByte}, v["lzo0"]...)},
		{CompressLZOStub, append([]byte{lzoCompressByte}, v["lzo0"]...)},
		{CompressLZ4V2, append([]byte{compV2Indicator, compV2LZ4}, lz4...)},
		{CompressStubV2, append([]byte{compV2Indicator, compV2LZ4}, lz4...)},
		{CompressLZ4, swapped},
	}
	for _, c := range cases {
		got, err := (compressor{c.mode, AllowCompressionAsym}).unframe(append([]byte(nil), c.wire...))
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("%v: %v", c.mode, err)
		}
		if _, err := (compressor{c.mode, AllowCompressionNo}).unframe(append([]byte(nil), c.wire...)); err == nil {
			t.Errorf("%v: allow-compression no accepted compressed data", c.mode)
		}
	}
}

func TestParseCompress(t *testing.T) {
	for _, c := range []struct {
		dir, arg string
		want     Compress
		push     string
	}{
		{"compress", "", CompressStub, "compress stub"},
		{"compress", "lz4-v2", CompressLZ4V2, "compress lz4-v2"},
		{"compress", "lzo", CompressLZO, "comp-lzo yes"},
		{"compress", "migrate", CompressUnset, ""},
		{"comp-lzo", "", CompressLZO, "comp-lzo yes"},
		{"comp-lzo", "adaptive", CompressLZO, "comp-lzo yes"},
		{"comp-lzo", "no", CompressLZOStub, "comp-lzo no"},
	} {
		got, err := ParseCompress(c.dir, c.arg)
		if err != nil || got != c.want || got.PushOption() != c.push {
			t.Errorf("%s %s = %v (%q), %v", c.dir, c.arg, got, got.PushOption(), err)
		}
	}
	if _, err := ParseCompress("compress", "snappy"); err == nil {
		t.Error("snappy accepted")
	}
}
