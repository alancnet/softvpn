package ovpn

import (
	"encoding/binary"
	"errors"
)

// The LZ4 block format and LZO1X decompression, as OpenVPN uses them for
// "compress lz4", "compress lz4-v2" and "comp-lzo". Each data-channel
// payload is one self-contained block.

var (
	errLZ4 = errors.New("corrupt LZ4 block")
	errLZO = errors.New("corrupt LZO1X block")
)

// lz4Decompress decodes one LZ4 block of at most max bytes.
func lz4Decompress(in []byte, max int) ([]byte, error) {
	out := make([]byte, 0, min(4*len(in), max))
	length := func(i, n int) (int, int, error) {
		if n != 15 {
			return i, n, nil
		}
		for {
			if i >= len(in) {
				return 0, 0, errLZ4
			}
			b := in[i]
			i++
			n += int(b)
			if b != 255 {
				return i, n, nil
			}
		}
	}
	i := 0
	for {
		if i >= len(in) {
			return nil, errLZ4
		}
		tok := in[i]
		i++
		var n int
		var err error
		if i, n, err = length(i, int(tok>>4)); err != nil {
			return nil, err
		}
		if n > len(in)-i || n > max-len(out) {
			return nil, errLZ4
		}
		out = append(out, in[i:i+n]...)
		i += n
		if i == len(in) {
			return out, nil // the last sequence has literals only
		}
		if i+2 > len(in) {
			return nil, errLZ4
		}
		off := int(binary.LittleEndian.Uint16(in[i:]))
		i += 2
		if off == 0 || off > len(out) {
			return nil, errLZ4
		}
		if i, n, err = length(i, int(tok&15)); err != nil {
			return nil, err
		}
		n += 4
		if n > max-len(out) {
			return nil, errLZ4
		}
		if off >= n {
			s := len(out) - off
			out = append(out, out[s:s+n]...)
		} else {
			for j := 0; j < n; j++ {
				out = append(out, out[len(out)-off])
			}
		}
	}
}

// lz4Compress encodes src as one LZ4 block with a simple greedy matcher. It
// returns nil if that doesn't make src smaller.
func lz4Compress(src []byte) []byte {
	const (
		minMatch = 4
		mfLimit  = 12 // no match may start in the last 12 bytes
		lastLits = 5  // the last 5 bytes are always literals
		hashLog  = 12
	)
	out := make([]byte, 0, len(src))
	emitLen := func(n int) {
		for ; n >= 255; n -= 255 {
			out = append(out, 255)
		}
		out = append(out, byte(n))
	}
	emit := func(lits []byte, off, mlen int) {
		tok := byte(min(len(lits), 15)) << 4
		if off > 0 {
			tok |= byte(min(mlen-minMatch, 15))
		}
		out = append(out, tok)
		if len(lits) >= 15 {
			emitLen(len(lits) - 15)
		}
		out = append(out, lits...)
		if off > 0 {
			out = binary.LittleEndian.AppendUint16(out, uint16(off))
			if mlen-minMatch >= 15 {
				emitLen(mlen - minMatch - 15)
			}
		}
	}
	var table [1 << hashLog]int32 // position+1 of the last occurrence
	anchor := 0
	for i := 0; i+mfLimit < len(src); {
		seq := binary.LittleEndian.Uint32(src[i:])
		h := seq * 2654435761 >> (32 - hashLog)
		ref := int(table[h]) - 1
		table[h] = int32(i + 1)
		if ref < 0 || i-ref > 65535 || binary.LittleEndian.Uint32(src[ref:]) != seq {
			i++
			continue
		}
		m := minMatch
		for i+m < len(src)-lastLits && src[ref+m] == src[i+m] {
			m++
		}
		emit(src[anchor:i], i-ref, m)
		i += m
		anchor = i
		if len(out) >= len(src) {
			return nil
		}
	}
	emit(src[anchor:], 0, 0)
	if len(out) >= len(src) {
		return nil
	}
	return out
}

// lzo1xDecompress decodes one LZO1X block (as made by lzo1x_1_15_compress,
// which OpenVPN uses) of at most max bytes. It follows the reference
// decompressor's instruction set:
//
//	0..15   literal run (after a match: a short M1 match)
//	16..31  M4 match, distance up to 48 KiB (distance 0 ends the stream)
//	32..63  M3 match, distance up to 16 KiB
//	64..255 M2 match, distance up to 2 KiB
//
// Every match's low two bits give 0-3 literals that follow it.
func lzo1xDecompress(in []byte, max int) ([]byte, error) {
	out := make([]byte, 0, min(4*len(in), max))
	ip := 0
	literals := func(n int) error {
		if n > len(in)-ip || n > max-len(out) {
			return errLZO
		}
		out = append(out, in[ip:ip+n]...)
		ip += n
		return nil
	}
	// extended adds a zero-run-encoded length: 255 per zero byte, then the
	// first non-zero byte.
	extended := func() (int, error) {
		n := 0
		for ip < len(in) && in[ip] == 0 {
			n += 255
			ip++
			if n > max {
				return 0, errLZO
			}
		}
		if ip >= len(in) {
			return 0, errLZO
		}
		n += int(in[ip])
		ip++
		return n, nil
	}
	le16 := func() (int, error) {
		if ip+2 > len(in) {
			return 0, errLZO
		}
		v := int(binary.LittleEndian.Uint16(in[ip:]))
		ip += 2
		return v, nil
	}

	if len(in) < 3 {
		return nil, errLZO
	}
	// state is the number of literals copied after the last instruction (4
	// meaning "4 or more"); it changes the meaning of codes 0..15.
	state := 0
	if in[0] > 17 {
		n := int(in[0]) - 17
		ip = 1
		if err := literals(n); err != nil {
			return nil, err
		}
		state = min(n, 4)
	}
	for {
		if ip >= len(in) {
			return nil, errLZO
		}
		t := int(in[ip])
		ip++
		var dist, n, next int
		switch {
		case t < 16 && state == 0: // literal run of 4 or more
			n = t
			if t == 0 {
				e, err := extended()
				if err != nil {
					return nil, err
				}
				n = 15 + e
			}
			if err := literals(n + 3); err != nil {
				return nil, err
			}
			state = 4
			continue
		case t < 16: // M1: right after literals
			if ip >= len(in) {
				return nil, errLZO
			}
			next = t & 3
			dist = 1 + t>>2 + int(in[ip])<<2
			ip++
			n = 2
			if state == 4 {
				dist += 0x800
				n = 3
			}
		case t >= 64: // M2
			if ip >= len(in) {
				return nil, errLZO
			}
			next = t & 3
			dist = 1 + (t>>2)&7 + int(in[ip])<<3
			ip++
			n = t>>5 + 1
		case t >= 32: // M3
			n = t&31 + 2
			if n == 2 {
				e, err := extended()
				if err != nil {
					return nil, err
				}
				n += 31 + e
			}
			v, err := le16()
			if err != nil {
				return nil, err
			}
			dist = 1 + v>>2
			next = v & 3
		default: // M4
			n = t&7 + 2
			if n == 2 {
				e, err := extended()
				if err != nil {
					return nil, err
				}
				n += 7 + e
			}
			v, err := le16()
			if err != nil {
				return nil, err
			}
			dist = (t&8)<<11 + v>>2
			next = v & 3
			if dist == 0 { // end of stream marker
				if n != 3 || ip != len(in) {
					return nil, errLZO
				}
				return out, nil
			}
			dist += 0x4000
		}
		if dist > len(out) || n > max-len(out) {
			return nil, errLZO
		}
		for j := 0; j < n; j++ {
			out = append(out, out[len(out)-dist])
		}
		if err := literals(next); err != nil {
			return nil, err
		}
		state = next
	}
}
