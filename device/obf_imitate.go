package device

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

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

// deviceImitate is the device-level imitation config. proto is stored via UAPI
// under ipcMutex and read lock-free on the send path (atomic.Uint32), matching
// the existing lock-free paddings/junk reads.
type deviceImitate struct {
	proto atomic.Uint32 // imitateProto
}

func parseImitateProto(s string) (imitateProto, error) {
	switch s {
	case "", "none":
		return imitateNone, nil
	case "quic":
		return imitateQUIC, nil
	case "dns":
		return imitateDNS, nil
	case "stun":
		return imitateSTUN, nil
	case "sip":
		return imitateSIP, nil
	}
	return imitateNone, fmt.Errorf("unknown imitate protocol %q", s)
}

func imitateProtoName(p imitateProto) string {
	switch p {
	case imitateQUIC:
		return "quic"
	case imitateDNS:
		return "dns"
	case imitateSTUN:
		return "stun"
	case imitateSIP:
		return "sip"
	}
	return "none"
}

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

const (
	dnsHeaderLen       = 12
	dnsRootQuestionLen = 5
	dnsOptFixedLen     = 11
	dnsOptOptionHdrLen = 4
	dnsOptMin          = dnsHeaderLen + dnsRootQuestionLen + dnsOptFixedLen + dnsOptOptionHdrLen // 32
	dnsOptUDPSize      = 1232
	dnsOptCoverCode    = 0xFDE9
)

func clampU16(v int) uint16 {
	if v < 0 {
		return 0
	}
	if v > 0xFFFF {
		return 0xFFFF
	}
	return uint16(v)
}

// writeDNS emits an EDNS OPT-framed DNS response (no-echo path only — a client has
// no incoming query to echo). The TXID comes from the payload, not the PRNG seed,
// so `seed` is unused. Byte-exact port of transform.rs apply_dns_padding (echo=None).
func writeDNS(buf []byte, padding int, seed uint32) {
	_ = seed
	if padding == 0 {
		return
	}
	if padding < dnsOptMin {
		writeDNSNull(buf, padding)
		return
	}
	total := len(buf)
	p := buf[:padding]
	payload := buf[padding:]

	var txid [2]byte
	if len(payload) > 0 {
		txid[0] = payload[0]
	}
	if len(payload) > 1 {
		txid[1] = payload[1]
	}
	question := []byte{0x00, 0x00, 0x01, 0x00, 0x01} // root QNAME + QTYPE A + QCLASS IN
	writeDNSOptResponse(p, total, txid, question)
}

func writeDNSOptResponse(p []byte, total int, txid [2]byte, question []byte) {
	optOff := dnsHeaderLen + len(question)                                     // 17 for a root question
	rdlength := clampU16(total - (optOff + dnsOptFixedLen))                    // total - 28
	optLen := clampU16(total - (optOff + dnsOptFixedLen + dnsOptOptionHdrLen)) // total - 32

	// Header (12 B).
	p[0] = txid[0]
	p[1] = txid[1]
	p[2] = 0x81 // QR=1, RD=1
	p[3] = 0x80 // RA=1, NOERROR
	p[4] = 0x00
	p[5] = 0x01 // QDCOUNT=1
	p[6] = 0x00
	p[7] = 0x00 // ANCOUNT=0
	p[8] = 0x00
	p[9] = 0x00 // NSCOUNT=0
	p[10] = 0x00
	p[11] = 0x01 // ARCOUNT=1

	copy(p[dnsHeaderLen:optOff], question)

	opt := [dnsOptFixedLen + dnsOptOptionHdrLen]byte{
		0x00,       // NAME: root label
		0x00, 0x29, // TYPE OPT (41)
		byte(dnsOptUDPSize >> 8), byte(dnsOptUDPSize & 0xFF), // CLASS = UDP size 1232
		0x00, 0x00, 0x00, 0x00, // TTL field 0
		byte(rdlength >> 8), byte(rdlength), // RDLENGTH
		byte(dnsOptCoverCode >> 8), byte(dnsOptCoverCode & 0xFF), // OPTION-CODE 0xFDE9
		byte(optLen >> 8), byte(optLen), // OPTION-LENGTH
	}
	copy(p[optOff:optOff+len(opt)], opt[:])

	for i := optOff + len(opt); i < len(p); i++ {
		p[i] = 0x00 // zero-fill option-data prefix
	}
}

// writeDNSNull is the legacy TYPE NULL fallback for padding < dnsOptMin.
// Byte-exact port of transform.rs apply_dns_padding_null.
func writeDNSNull(buf []byte, padding int) {
	total := len(buf)
	p := buf[:padding]
	payload := buf[padding:]
	if len(p) == 0 {
		return
	}
	var txHi, txLo byte
	if len(payload) > 0 {
		txHi = payload[0]
	}
	if len(payload) > 1 {
		txLo = payload[1]
	}
	var qdcount, ancount byte
	if padding >= 17 {
		qdcount = 1
	}
	if padding >= 28 {
		ancount = 1
	}
	rdlength := clampU16(total - 28) // saturating
	fixed := [28]byte{
		txHi, txLo,
		0x81, 0x80, // QR=1, RD=1, RA=1, NOERROR
		0x00, qdcount,
		0x00, ancount,
		0x00, 0x00,
		0x00, 0x00,
		0x00,       // QNAME root label
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
		0x00,       // answer NAME root label
		0x00, 0x0a, // TYPE NULL (10)
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		byte(rdlength >> 8), byte(rdlength),
	}
	advertised := 12
	if padding >= 28 {
		advertised = 28
	} else if padding >= 17 {
		advertised = 17
	}
	copyLen := advertised
	if len(p) < copyLen {
		copyLen = len(p)
	}
	copy(p[:copyLen], fixed[:copyLen])
	for i := copyLen; i < len(p); i++ {
		p[i] = 0x00
	}
}

func decimalDigits(value int) int {
	digits := 1
	for value >= 10 {
		value /= 10
		digits++
	}
	return digits
}

// writeSIP emits a SIP response header block. Byte-exact port of
// transform.rs apply_sip_padding. The LCG draw order (status/host/method/branch/
// from-tag/to-tag/call-id, then cseq reads state directly) must not change.
func writeSIP(buf []byte, padding int, seed uint32) {
	totalLen := len(buf)
	p := buf[:padding]
	if len(p) == 0 {
		return
	}
	length := len(p)

	st := seed
	next := func() uint32 {
		v := st
		st = lcgStep(st)
		return v
	}
	status := []string{"100 Trying", "180 Ringing", "200 OK"}
	hosts := []string{"sip.example.com", "pbx.example.net", "voip.example.org"}
	methods := []string{"INVITE", "OPTIONS", "REGISTER"}
	statusIdx := int(next()) % len(status)
	host := hosts[int(next())%len(hosts)]
	method := methods[int(next())%len(methods)]
	branch := next()
	fromTag := next()
	toTag := next()
	callID := next()
	cseq := 1 + (st % 100000) // reads state directly; no further next()

	pos := 0
	// putLine writes a CRLF-terminated line iff it + the 2-byte closing blank line
	// still fit in the padding region.
	putLine := func(line string) bool {
		n := len(line)
		if pos+n+2 <= length {
			copy(p[pos:pos+n], line)
			pos += n
			return true
		}
		return false
	}

	statusWritten := false
	for k := 0; k < len(status); k++ {
		s := status[(statusIdx+k)%len(status)]
		if putLine(fmt.Sprintf("SIP/2.0 %s\r\n", s)) {
			statusWritten = true
			break
		}
	}
	if !statusWritten {
		frag := []byte("SIP/2.0 100 Trying\r\n")
		take := len(frag)
		if take > length {
			take = length
		}
		copy(p[:take], frag[:take])
		for i := take; i < length; i++ {
			p[i] = ' '
		}
		if length >= 2 {
			p[length-2] = '\r'
			p[length-1] = '\n'
		}
		return
	}

	allMandatory :=
		putLine(fmt.Sprintf("Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK%08x;rport\r\n", host, branch)) &&
			putLine(fmt.Sprintf("From: <sip:caller@%s>;tag=%08x\r\n", host, fromTag)) &&
			putLine(fmt.Sprintf("To: <sip:callee@%s>;tag=%08x\r\n", host, toTag)) &&
			putLine(fmt.Sprintf("Call-ID: %08x@%s\r\n", callID, host)) &&
			putLine(fmt.Sprintf("CSeq: %d %s\r\n", cseq, method))

	if allMandatory {
	contentLength:
		for sws := 1; sws <= 2; sws++ {
			for digits := 1; digits <= decimalDigits(totalLen); digits++ {
				headerEnd := pos + len("Content-Length:") + sws + digits + len("\r\n\r\n")
				if headerEnd > length {
					break
				}
				if decimalDigits(totalLen-headerEnd) == digits {
					body := totalLen - headerEnd
					if sws == 1 {
						putLine(fmt.Sprintf("Content-Length: %d\r\n", body))
					} else {
						putLine(fmt.Sprintf("Content-Length:  %d\r\n", body))
					}
					break contentLength
				}
			}
		}
	}

	if pos+2 <= length {
		p[pos] = '\r'
		p[pos+1] = '\n'
		pos += 2
	}
	for i := pos; i < length; i++ {
		p[i] = ' '
	}
}

// fillPadding rewrites buf[:padding] — protocol-conformant filler when an imitate
// protocol is configured, otherwise the original random padding. Read of proto is
// lock-free (atomic), never the config lock. Callers must pass a buf whose tail
// buf[padding:] is exactly the real packet: the DNS/STUN/SIP/QUIC writers seed the
// PRNG from those bytes, so trailing slack (e.g. a full pooled array) would seed
// from stale memory.
func (device *Device) fillPadding(buf []byte, padding int) {
	if p := imitateProto(device.imitate.proto.Load()); p != imitateNone {
		imitateFillPrefix(buf, padding, p)
	} else {
		rand.Read(buf[:padding])
	}
}
