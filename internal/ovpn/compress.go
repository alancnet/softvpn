package ovpn

import (
	"errors"
	"fmt"
	"strings"
)

// Compress is a data-channel compression setting ("compress ALGO" or
// "comp-lzo MODE"). It decides the framing: OpenVPN puts a small header in
// front of every data-channel payload once compression is configured, even
// when nothing is actually compressed.
type Compress uint8

const (
	CompressUnset   Compress = iota // no directive: no framing (see migrate)
	CompressStub                    // compress / compress stub: 1-byte header, swapped
	CompressStubV2                  // compress stub-v2: v2 escape framing
	CompressLZ4                     // compress lz4: 1-byte header, swapped
	CompressLZ4V2                   // compress lz4-v2: v2 escape framing
	CompressLZO                     // comp-lzo [yes|adaptive], compress lzo: 1-byte header
	CompressLZOStub                 // comp-lzo no: 1-byte header, never compressed
)

// AllowCompression is "allow-compression": whether compressed packets are
// accepted (asym, the default), also sent (yes), or refused (no). Sending
// compressed data enables VORACLE-style attacks, so only "yes" does it.
type AllowCompression uint8

const (
	AllowCompressionAsym AllowCompression = iota
	AllowCompressionNo
	AllowCompressionYes
)

// Header bytes, from OpenVPN's comp.h.
const (
	noCompressByte     = 0xfa // V1, uncompressed
	noCompressByteSwap = 0xfb // V1 swap framing, uncompressed
	lzoCompressByte    = 0x66
	lz4CompressByte    = 0x69
	compV2Indicator    = 0x50 // V2: 0x50 ALG, only when needed
	compV2Uncompressed = 0
	compV2LZ4          = 1

	// compressThreshold is the smallest payload OpenVPN tries to compress.
	compressThreshold = 100
	// maxDecompressed bounds decompressed payloads (an IP packet).
	maxDecompressed = 65535
)

// ParseCompress parses the "compress" and "comp-lzo" directives. "compress
// migrate" is CompressUnset: softvpn always migrates clients that announce
// compression (see setCompression).
func ParseCompress(directive, arg string) (Compress, error) {
	switch directive {
	case "compress":
		switch strings.ToLower(arg) {
		case "", "stub":
			return CompressStub, nil
		case "stub-v2":
			return CompressStubV2, nil
		case "lz4":
			return CompressLZ4, nil
		case "lz4-v2":
			return CompressLZ4V2, nil
		case "lzo":
			return CompressLZO, nil
		case "migrate":
			return CompressUnset, nil
		}
		return 0, fmt.Errorf("unsupported algorithm %q (use stub, stub-v2, lz4, lz4-v2, lzo or migrate)", arg)
	case "comp-lzo":
		switch strings.ToLower(arg) {
		case "", "yes", "adaptive":
			return CompressLZO, nil
		case "no":
			return CompressLZOStub, nil
		}
		return 0, fmt.Errorf("expects yes, no or adaptive")
	}
	return 0, fmt.Errorf("not a compression directive: %s", directive)
}

// ParseAllowCompression parses "allow-compression no|asym|yes".
func ParseAllowCompression(arg string) (AllowCompression, error) {
	switch strings.ToLower(arg) {
	case "no":
		return AllowCompressionNo, nil
	case "asym":
		return AllowCompressionAsym, nil
	case "yes":
		return AllowCompressionYes, nil
	}
	return 0, fmt.Errorf("expects no, asym or yes")
}

// Stub reports whether c only frames and never carries compressed data.
func (c Compress) Stub() bool {
	return c == CompressUnset || c == CompressStub || c == CompressStubV2 || c == CompressLZOStub
}

// PushOption is the option that tells a client to use the same framing.
// LZO uses the comp-lzo spelling, which OpenVPN 2.3 also understands.
func (c Compress) PushOption() string {
	switch c {
	case CompressStub:
		return "compress stub"
	case CompressStubV2:
		return "compress stub-v2"
	case CompressLZ4:
		return "compress lz4"
	case CompressLZ4V2:
		return "compress lz4-v2"
	case CompressLZO:
		return "comp-lzo yes"
	case CompressLZOStub:
		return "comp-lzo no"
	}
	return ""
}

func (c Compress) String() string {
	if c == CompressUnset {
		return "none"
	}
	return c.PushOption()
}

// compressor applies one session's compression framing.
type compressor struct {
	mode  Compress
	allow AllowCompression
}

var errDecompress = errors.New("bad compression framing")

// frame wraps an outgoing payload. Data is only compressed (with LZ4) when
// allow-compression is yes; LZO framing always sends it uncompressed, which
// every LZO peer accepts.
func (c compressor) frame(p []byte) []byte {
	compress := c.allow == AllowCompressionYes && len(p) >= compressThreshold
	switch c.mode {
	case CompressStubV2, CompressLZ4V2:
		if c.mode == CompressLZ4V2 && compress {
			if z := lz4Compress(p); z != nil {
				return append([]byte{compV2Indicator, compV2LZ4}, z...)
			}
		}
		// The V2 header is only added to payloads that would look like one.
		if len(p) > 0 && p[0] == compV2Indicator {
			return append([]byte{compV2Indicator, compV2Uncompressed}, p...)
		}
		return p
	case CompressStub, CompressLZ4:
		// Swap framing: the header takes the first byte's place and that
		// byte moves to the end, keeping the payload aligned.
		head := byte(noCompressByteSwap)
		if c.mode == CompressLZ4 && compress {
			if z := lz4Compress(p); z != nil {
				p, head = z, lz4CompressByte
			}
		}
		if len(p) == 0 {
			return p
		}
		out := make([]byte, len(p)+1)
		out[0] = head
		copy(out[1:], p[1:])
		out[len(p)] = p[0]
		return out
	case CompressLZO, CompressLZOStub:
		return append([]byte{noCompressByte}, p...)
	}
	return p
}

// unframe undoes frame on an incoming payload (in place), decompressing it
// unless allow-compression is no. Any algorithm valid for the framing is
// accepted, as OpenVPN does when the peer compresses and we don't.
func (c compressor) unframe(p []byte) ([]byte, error) {
	if len(p) == 0 {
		return p, nil
	}
	var head byte
	switch c.mode {
	case CompressUnset:
		return p, nil
	case CompressStubV2, CompressLZ4V2:
		if p[0] != compV2Indicator {
			return p, nil
		}
		if len(p) < 2 {
			return nil, errDecompress
		}
		switch p[1] {
		case compV2Uncompressed:
			return p[2:], nil
		case compV2LZ4:
			return c.decompress(lz4Decompress, p[2:])
		}
		return nil, errDecompress
	case CompressStub, CompressLZ4:
		head = p[0]
		p[0] = p[len(p)-1]
		p = p[:len(p)-1]
		switch head {
		case noCompressByteSwap:
			return p, nil
		case lz4CompressByte:
			return c.decompress(lz4Decompress, p)
		}
	case CompressLZO, CompressLZOStub:
		head, p = p[0], p[1:]
		switch head {
		case noCompressByte:
			return p, nil
		case lzoCompressByte:
			return c.decompress(lzo1xDecompress, p)
		}
	}
	return nil, fmt.Errorf("%w: unknown header byte 0x%02x", errDecompress, head)
}

func (c compressor) decompress(f func([]byte, int) ([]byte, error), p []byte) ([]byte, error) {
	if c.allow == AllowCompressionNo {
		return nil, errors.New("compressed packet refused (allow-compression no)")
	}
	return f(p, maxDecompressed)
}

// setCompression picks the session's compression framing once the
// application has assigned the client. An explicit setting is pushed so the
// client frames the same way; a "compress" or "comp-lzo" option the
// application already pushes is honoured instead. Without either, a client
// that has compression enabled is migrated to framing without compression,
// like OpenVPN's "compress migrate".
func (s *Session) setCompression(a *Assignment) {
	mode, push := a.Compress, true
	for _, o := range a.Push {
		f := strings.Fields(o)
		if len(f) > 0 && (f[0] == "compress" || f[0] == "comp-lzo") {
			if m, err := ParseCompress(f[0], strings.Join(f[1:], " ")); err == nil {
				mode, push = m, false
			}
		}
	}
	switch {
	case !push:
	case mode == CompressUnset && s.clientComp:
		mode = CompressLZOStub
		if s.pi["IV_COMP_STUBv2"] == "1" {
			mode = CompressStubV2
		}
	case mode != CompressUnset && mode != CompressLZO && mode != CompressLZOStub && s.pi["IV_COMP_STUB"] != "1":
		// OpenVPN before 2.4 only knows comp-lzo.
		mode = CompressLZOStub
	}
	if push {
		s.compPush = mode.PushOption()
	}
	s.comp = compressor{mode, s.srv.opt.AllowCompression}
}
