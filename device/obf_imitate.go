package device

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

// Temporary stubs — replaced by real implementations in Tasks 3–5.
func writeDNS(buf []byte, padding int, seed uint32)  {}
func writeSTUN(buf []byte, padding int, seed uint32) {}
func writeSIP(buf []byte, padding int, seed uint32)  {}
