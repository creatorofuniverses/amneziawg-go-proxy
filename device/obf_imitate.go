package device

import "encoding/binary"

// imitateProto selects the protocol that S-padding (and, in later tiers, junk
// and I-packets) is shaped to resemble. The zero value imitateNone preserves the
// original rand.Read behavior.
type imitateProto uint8

const (
	imitateNone imitateProto = iota
	imitateQUIC
	imitateDNS
	imitateSTUN
	imitateSIP
)

// fnv1aSeed is the FNV-1a 32-bit hash of the first 64 bytes of payload. It seeds
// the per-packet PRNG for QUIC/STUN/SIP. Byte-exact port of transform.rs fnv1a_seed.
func fnv1aSeed(payload []byte) uint32 {
	state := uint32(0x811c9dc5)
	n := len(payload)
	if n > 64 {
		n = 64
	}
	for _, b := range payload[:n] {
		state ^= uint32(b)
		state *= 0x01000193
	}
	return state
}

// lcgStep is the glibc linear congruential generator step. uint32 arithmetic
// wraps natively, which is required for byte-exactness.
func lcgStep(state uint32) uint32 {
	return state*1103515245 + 12345
}

// imitateFillPrefix rewrites buf[:padding] with protocol-conformant filler for p,
// seeding from the real payload at buf[padding:]. Byte-exact port of
// transform.rs apply_padding, including its no-op guard. Writes exactly `padding`
// bytes; buf[padding:] is never modified.
func imitateFillPrefix(buf []byte, padding int, p imitateProto) {
	if padding == 0 || padding >= len(buf) {
		return
	}
	seed := fnv1aSeed(buf[padding:])
	imitateFill(buf, padding, seed, p)
}

// imitateFill dispatches to the protocol writer. `seed` is the initial PRNG state
// for QUIC/STUN/SIP; the DNS writer derives its TXID from buf[padding:] directly
// and ignores seed.
func imitateFill(buf []byte, padding int, seed uint32, p imitateProto) {
	switch p {
	case imitateQUIC:
		writeQUICShort(buf, padding, seed)
	case imitateDNS:
		writeDNS(buf, padding, seed)
	case imitateSTUN:
		writeSTUN(buf, padding, seed)
	case imitateSIP:
		writeSIP(buf, padding, seed)
	}
}

// writeQUICShort emits a QUIC 1-RTT short header (RFC 9000 §17.3.1) followed by
// pseudo-random bytes. Byte-exact port of transform.rs apply_quic_padding_short.
func writeQUICShort(buf []byte, padding int, seed uint32) {
	p := buf[:padding]
	if len(p) == 0 {
		return
	}
	state := seed

	// Short header first byte: 0 1 S R R K P P
	// form=0, fixed=1, spin=random, reserved=00, key_phase=random, pn_len=random.
	spin := uint8(state>>8) & 0x01
	state = lcgStep(state)
	keyPhase := uint8(state>>8) & 0x01
	state = lcgStep(state)
	pnLenBits := uint8(state) & 0x03
	state = lcgStep(state)

	p[0] = 0x40 | (spin << 5) | (keyPhase << 2) | pnLenBits

	for i := 1; i < len(p); i++ {
		p[i] = uint8(state >> 16) // middle byte, NOT the low byte
		state = lcgStep(state)
	}
}

// writeSTUN emits a STUN Binding Success Response. Byte-exact port of
// transform.rs apply_stun_padding. Attributes are written into [20, 20+written)
// before the header, which lives in [0,20) — no overlap.
func writeSTUN(buf []byte, padding int, seed uint32) {
	p := buf[:padding]
	if len(p) == 0 {
		return
	}
	state := seed
	next := func() uint32 {
		v := state
		state = lcgStep(state)
		return v
	}
	const cookie uint32 = 0x2112A442

	// Transaction ID — 3 LCG steps, consumed before any attribute randomness so
	// it is stable across pad sizes.
	var txn [12]byte
	for i := 0; i < 12; i += 4 {
		binary.BigEndian.PutUint32(txn[i:i+4], next())
	}

	body := 0
	if padding > 20 {
		body = (padding - 20) &^ 0b11 // STUN message length is a multiple of 4
	}
	written := 0

	// XOR-MAPPED-ADDRESS (0x0020), IPv4: 4-byte header + 8-byte value.
	if body-written >= 12 {
		port := uint16(next() >> 16)
		addr := next()
		xport := port ^ uint16(cookie>>16)
		xaddr := addr ^ cookie
		off := 20 + written
		binary.BigEndian.PutUint16(p[off:off+2], 0x0020)
		binary.BigEndian.PutUint16(p[off+2:off+4], 8)
		p[off+4] = 0x00 // reserved
		p[off+5] = 0x01 // IPv4
		binary.BigEndian.PutUint16(p[off+6:off+8], xport)
		binary.BigEndian.PutUint32(p[off+8:off+12], xaddr)
		written += 12
	}

	// SOFTWARE (0x8022) fills the rest of body; value clamped to 124 (RFC 5389 §15.10).
	remaining := body - written
	if remaining >= 4 {
		vlen := remaining - 4
		if vlen > 124 {
			vlen = 124
		}
		off := 20 + written
		binary.BigEndian.PutUint16(p[off:off+2], 0x8022)
		binary.BigEndian.PutUint16(p[off+2:off+4], uint16(vlen))
		for j := 0; j < vlen; j++ {
			p[off+4+j] = 0x20 + byte(next()%0x5F) // printable ASCII
		}
		written += 4 + vlen
	}

	// Header — advertises `written` (TLV bytes), never `body`.
	var header [20]byte
	binary.BigEndian.PutUint16(header[0:2], 0x0101) // Binding Success Response
	binary.BigEndian.PutUint16(header[2:4], uint16(written))
	binary.BigEndian.PutUint32(header[4:8], cookie)
	copy(header[8:20], txn[:])
	copyLen := len(p)
	if copyLen > 20 {
		copyLen = 20
	}
	copy(p[:copyLen], header[:copyLen])

	// Zero any padding past the advertised message (undissected trailing bytes).
	for j := 20 + written; j < len(p); j++ {
		p[j] = 0x00
	}
}

// Temporary stubs — replaced by real implementations in Tasks 4–5.
func writeDNS(buf []byte, padding int, seed uint32) {}
func writeSIP(buf []byte, padding int, seed uint32) {}
