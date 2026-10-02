package ovpn

import "time"

// reliable is OpenVPN's control-channel reliability layer for one key
// state: numbered messages, ACKs, in-order delivery and (over UDP)
// retransmission. It is not safe for concurrent use; the owning Session
// serialises access.
type reliable struct {
	keyID      byte
	retransmit bool

	nextSendID uint32
	unacked    []*outMsg

	nextRecvID  uint32
	recvBuf     map[uint32]inMsg
	pendingAcks []uint32
}

type outMsg struct {
	id      uint32
	op      byte
	payload []byte
	sent    bool
	nextTx  time.Time
	rto     time.Duration
}

type inMsg struct {
	op      byte
	payload []byte
}

const (
	sendWindow = 6
	recvWindow = 12
	initialRTO = time.Second
	maxRTO     = 8 * time.Second
)

func newReliable(keyID byte, retransmit bool) *reliable {
	return &reliable{keyID: keyID, retransmit: retransmit, recvBuf: map[uint32]inMsg{}}
}

// enqueue queues a message, splitting payloads larger than one packet.
func (r *reliable) enqueue(op byte, payload []byte) {
	for {
		n := len(payload)
		if n > maxControlPayload {
			n = maxControlPayload
		}
		r.unacked = append(r.unacked, &outMsg{id: r.nextSendID, op: op, payload: append([]byte(nil), payload[:n]...)})
		r.nextSendID++
		payload = payload[n:]
		if len(payload) == 0 {
			return
		}
	}
}

// ack drops acknowledged messages from the send queue.
func (r *reliable) ack(ids []uint32) {
	if len(ids) == 0 {
		return
	}
	kept := r.unacked[:0]
	for _, m := range r.unacked {
		acked := false
		for _, id := range ids {
			if m.id == id {
				acked = true
				break
			}
		}
		if !acked {
			kept = append(kept, m)
		}
	}
	r.unacked = kept
}

// receive records an incoming message and returns the messages that are now
// deliverable in order.
func (r *reliable) receive(id uint32, op byte, payload []byte) []inMsg {
	if id-r.nextRecvID >= recvWindow && id >= r.nextRecvID {
		return nil // too far ahead: drop without ACK, the peer will resend
	}
	r.pendingAcks = append(r.pendingAcks, id)
	if id < r.nextRecvID {
		return nil // duplicate of something already delivered; re-ACK only
	}
	r.recvBuf[id] = inMsg{op: op, payload: append([]byte(nil), payload...)}
	var out []inMsg
	for {
		m, ok := r.recvBuf[r.nextRecvID]
		if !ok {
			return out
		}
		delete(r.recvBuf, r.nextRecvID)
		r.nextRecvID++
		out = append(out, m)
	}
}

func (r *reliable) takeAcks() []uint32 {
	n := len(r.pendingAcks)
	if n > maxAcksPerPacket {
		n = maxAcksPerPacket
	}
	acks := append([]uint32(nil), r.pendingAcks[:n]...)
	r.pendingAcks = r.pendingAcks[n:]
	return acks
}

// collect returns the wire packets due now: new or timed-out messages within
// the send window (each carrying piggybacked ACKs), then bare ACK packets
// for any ACKs left over.
func (r *reliable) collect(now time.Time, local, remote sessionID) [][]byte {
	var out [][]byte
	for i, m := range r.unacked {
		if i >= sendWindow {
			break
		}
		if m.sent && (!r.retransmit || now.Before(m.nextTx)) {
			continue
		}
		if !m.sent {
			m.rto = initialRTO
		} else if m.rto *= 2; m.rto > maxRTO {
			m.rto = maxRTO
		}
		m.sent = true
		m.nextTx = now.Add(m.rto)
		p := controlPacket{op: m.op, keyID: r.keyID, sid: local, acks: r.takeAcks(), ackedSID: remote, messageID: m.id, payload: m.payload}
		out = append(out, p.marshal())
	}
	for len(r.pendingAcks) > 0 {
		p := controlPacket{op: opAckV1, keyID: r.keyID, sid: local, acks: r.takeAcks(), ackedSID: remote}
		out = append(out, p.marshal())
	}
	return out
}
