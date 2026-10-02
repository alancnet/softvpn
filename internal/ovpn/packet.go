// Package ovpn implements the server side of the OpenVPN 2.x protocol,
// compatible with the stock openvpn client (2.5+), entirely in userspace.
//
// Every OpenVPN packet starts with one byte holding a 5-bit opcode and a
// 3-bit key id. Control packets carry a session id, an ACK list and a
// message id for the reliability layer, followed by a fragment of the TLS
// byte stream. Data packets carry IP packets, AEAD-encrypted (or CBC with
// HMAC for old clients) and optionally in OpenVPN's compression framing.
package ovpn

import (
	"encoding/binary"
	"errors"
)

const (
	opControlHardResetClientV1 = 1
	opControlHardResetServerV1 = 2
	opControlSoftResetV1       = 3
	opControlV1                = 4
	opAckV1                    = 5
	opDataV1                   = 6
	opControlHardResetClientV2 = 7
	opControlHardResetServerV2 = 8
	opDataV2                   = 9
	opControlHardResetClientV3 = 10
	opControlWKCV1             = 11
)

const (
	maxAcksPerPacket = 4
	// maxControlPayload is the TLS bytes carried per control packet; it keeps
	// control packets under OpenVPN's default tls-mtu of 1250.
	maxControlPayload = 1100
)

type sessionID [8]byte

// controlPacket is a decoded control or ACK packet.
type controlPacket struct {
	op        byte
	keyID     byte
	sid       sessionID // sender's session id
	acks      []uint32
	ackedSID  sessionID // receiver's session id, present when acks is non-empty
	messageID uint32    // absent for P_ACK_V1
	payload   []byte
}

var errShort = errors.New("packet too short")

func opcodeOf(b byte) byte { return b >> 3 }
func keyIDOf(b byte) byte  { return b & 0x07 }

func isControl(op byte) bool {
	switch op {
	case opControlHardResetClientV2, opControlSoftResetV1, opControlV1, opAckV1:
		return true
	}
	return false
}

func parseControl(b []byte) (*controlPacket, error) {
	if len(b) < 10 {
		return nil, errShort
	}
	p := &controlPacket{op: opcodeOf(b[0]), keyID: keyIDOf(b[0])}
	copy(p.sid[:], b[1:9])
	n := int(b[9])
	b = b[10:]
	if n > 8 || len(b) < n*4 {
		return nil, errShort
	}
	for i := 0; i < n; i++ {
		p.acks = append(p.acks, binary.BigEndian.Uint32(b[i*4:]))
	}
	b = b[n*4:]
	if n > 0 {
		if len(b) < 8 {
			return nil, errShort
		}
		copy(p.ackedSID[:], b[:8])
		b = b[8:]
	}
	if p.op != opAckV1 {
		if len(b) < 4 {
			return nil, errShort
		}
		p.messageID = binary.BigEndian.Uint32(b)
		b = b[4:]
	}
	p.payload = b
	return p, nil
}

func (p *controlPacket) marshal() []byte {
	size := 10 + 4*len(p.acks) + 4 + len(p.payload)
	if len(p.acks) > 0 {
		size += 8
	}
	b := make([]byte, 0, size)
	b = append(b, p.op<<3|p.keyID&0x07)
	b = append(b, p.sid[:]...)
	b = append(b, byte(len(p.acks)))
	for _, a := range p.acks {
		b = binary.BigEndian.AppendUint32(b, a)
	}
	if len(p.acks) > 0 {
		b = append(b, p.ackedSID[:]...)
	}
	if p.op != opAckV1 {
		b = binary.BigEndian.AppendUint32(b, p.messageID)
	}
	return append(b, p.payload...)
}

// Magic payloads carried inside the encrypted data channel.
var (
	pingMagic = []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
	occMagic  = []byte{0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c}
)

const occExit = 6
