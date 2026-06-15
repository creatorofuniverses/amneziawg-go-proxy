# Client-side Traffic Imitation — Tier 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add native QUIC/DNS/STUN/SIP traffic imitation to the `amneziawg-go` core for the S-padding (mechanism A) send path, byte-exact with the server-side `transform.rs`, gated behind a new `imitate_protocol` UAPI key (default `none` = today's behavior).

**Architecture:** A new self-contained `device/obf_imitate.go` ports `transform.rs` byte-for-byte: a shared FNV-1a + glibc-LCG PRNG and four protocol writers, behind one guarded prefix entry point `imitateFillPrefix`. A `device.fillPadding` helper swaps the four `rand.Read(buf[:padding])` S-padding sites in `send.go`. Byte-exactness is enforced by a golden-vector fixture generated from the Rust crate. Whole-datagram fill (junk/I-packets) and the `imitate_protocol` selector for those mechanisms are **out of scope** (Tiers 2–3).

**Tech Stack:** Go 1.24 (`device` package), `crypto/rand` (unchanged fallback), `sync/atomic`; Rust/cargo (one-time, to generate golden vectors from `amneziawg-install/amneziawg-proxy`).

**Reference docs:** spec `docs/superpowers/specs/2026-06-15-client-side-traffic-imitation-design.md`; review `docs/superpowers/reviews/2026-06-15-client-side-traffic-imitation-review.md`. Fill reference: `../amneziawg-install/amneziawg-proxy/src/transform.rs`.

**Naming note (avoids a Go collision):** proto **constants** are `imitateQUIC/imitateDNS/imitateSTUN/imitateSIP`; **writer functions** use the `write*` prefix (`writeQUICShort`, `writeDNS`, `writeDNSNull`, `writeSTUN`, `writeSIP`) so a function never shares a name with a const.

**General notes for every task:**
- Work on a branch off `master` (repo etiquette: PR + squash). Suggested: `git switch -c feat/client-imitation-tier1`.
- A PostToolUse hook runs `gofmt -w` on save; still run `go test ./device/...` before each commit. `go test ./...` includes `TestFormatting`, which fails on non-gofmt'd files.
- The new file `device/obf_imitate.go` has **no SPDX header** — matching the sibling `device/obf_*.go` files (verified: `obf_rand.go` starts directly with `package device`).
- Line numbers for `send.go`/`uapi.go` below are ground-truth as of this plan; if drifted, re-grep (`grep -n 'rand.Read' device/send.go`).

---

### Task 1: PRNG, proto type, and the guarded prefix entry point

**Files:**
- Create: `device/obf_imitate.go`
- Test: `device/obf_imitate_test.go`

- [ ] **Step 1: Write the failing PRNG tests**

Create `device/obf_imitate_test.go`:

```go
package device

import "testing"

func TestFnv1aSeed(t *testing.T) {
	// Empty input → bare FNV-1a 32-bit offset basis.
	if got := fnv1aSeed(nil); got != 0x811c9dc5 {
		t.Fatalf("fnv1aSeed(nil) = %#x, want 0x811c9dc5", got)
	}
	// Only the first 64 bytes are consumed.
	long := make([]byte, 100)
	for i := range long {
		long[i] = byte(i)
	}
	if fnv1aSeed(long) != fnv1aSeed(long[:64]) {
		t.Fatal("fnv1aSeed must hash at most the first 64 bytes")
	}
}

func TestLcgStep(t *testing.T) {
	cases := []struct {
		in, want uint32
	}{
		{0, 12345},                  // 0*A + C
		{1, 1103527590},             // 1103515245 + 12345
		{0xFFFFFFFF, 3191464396},    // wraparound: must be uint32 modular arithmetic
	}
	for _, c := range cases {
		if got := lcgStep(c.in); got != c.want {
			t.Errorf("lcgStep(%#x) = %d, want %d", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./device/ -run 'TestFnv1aSeed|TestLcgStep' -v`
Expected: FAIL — `undefined: fnv1aSeed` / `undefined: lcgStep`.

- [ ] **Step 3: Create `device/obf_imitate.go` with the PRNG, types, and entry point**

```go
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
```

Note: this won't compile yet — the four `write*` functions are added in Tasks 2–5. Add a temporary stub block at the end of the file so Task 1 compiles in isolation:

```go
// Temporary stubs — replaced by real implementations in Tasks 2–5.
func writeQUICShort(buf []byte, padding int, seed uint32) {}
func writeDNS(buf []byte, padding int, seed uint32)       {}
func writeSTUN(buf []byte, padding int, seed uint32)      {}
func writeSIP(buf []byte, padding int, seed uint32)       {}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./device/ -run 'TestFnv1aSeed|TestLcgStep' -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add device/obf_imitate.go device/obf_imitate_test.go
git commit -m "feat(imitate): PRNG, imitateProto, and guarded prefix entry point"
```

---

### Task 2: QUIC 1-RTT short-header writer

**Files:**
- Modify: `device/obf_imitate.go` (replace the `writeQUICShort` stub)
- Test: `device/obf_imitate_test.go`

- [ ] **Step 1: Write the failing test**

Append to `device/obf_imitate_test.go`:

```go
func TestWriteQUICShort(t *testing.T) {
	// pad_size=10, payload after it untouched (form=0/fixed=1, reserved cleared).
	buf := make([]byte, 20)
	for i := 10; i < 20; i++ {
		buf[i] = 0xAA
	}
	imitateFillPrefix(buf, 10, imitateQUIC)

	if buf[0]&0xC0 != 0x40 {
		t.Errorf("byte0 form/fixed = %#x, want high bits 0x40", buf[0])
	}
	if buf[0]&0x18 != 0x00 {
		t.Errorf("byte0 reserved bits = %#x, want 0 (RFC 9000 §17.3)", buf[0]&0x18)
	}
	for i := 10; i < 20; i++ {
		if buf[i] != 0xAA {
			t.Fatalf("payload byte %d mutated to %#x", i, buf[i])
		}
	}
}

func TestWriteQUICShortVariesWithPayload(t *testing.T) {
	a := make([]byte, 20)
	b := make([]byte, 20)
	for i := 10; i < 20; i++ {
		a[i] = 0xAA
		b[i] = 0xBB
	}
	imitateFillPrefix(a, 10, imitateQUIC)
	imitateFillPrefix(b, 10, imitateQUIC)
	same := true
	for i := 0; i < 10; i++ {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("QUIC padding must vary with payload seed")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./device/ -run TestWriteQUICShort -v`
Expected: FAIL — stub leaves `buf[0] == 0x00`, so `buf[0]&0xC0 != 0x40`.

- [ ] **Step 3: Replace the `writeQUICShort` stub with the real implementation**

In `device/obf_imitate.go`, replace `func writeQUICShort(buf []byte, padding int, seed uint32) {}` with:

```go
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./device/ -run TestWriteQUICShort -v`
Expected: PASS (both QUIC tests).

- [ ] **Step 5: Commit**

```bash
git add device/obf_imitate.go device/obf_imitate_test.go
git commit -m "feat(imitate): QUIC 1-RTT short-header writer"
```

---

### Task 3: STUN Binding Success Response writer

**Files:**
- Modify: `device/obf_imitate.go` (replace the `writeSTUN` stub; add `encoding/binary` import)
- Test: `device/obf_imitate_test.go`

- [ ] **Step 1: Write the failing test**

Append to `device/obf_imitate_test.go`:

```go
import "encoding/binary" // add to the existing import block if not present

func TestWriteSTUNHeaderOnly(t *testing.T) {
	// pad_size==20: a bare valid 20-byte Binding Success Response, length 0.
	buf := make([]byte, 28)
	for i := 20; i < 28; i++ {
		buf[i] = 0xAB
	}
	imitateFillPrefix(buf, 20, imitateSTUN)

	if binary.BigEndian.Uint16(buf[0:2]) != 0x0101 {
		t.Errorf("type = %#x, want 0x0101 (Binding Success Response)", buf[0:2])
	}
	if binary.BigEndian.Uint16(buf[2:4]) != 0 {
		t.Errorf("length = %d, want 0 (no attributes fit)", binary.BigEndian.Uint16(buf[2:4]))
	}
	if binary.BigEndian.Uint32(buf[4:8]) != 0x2112A442 {
		t.Errorf("magic cookie = %#x, want 0x2112A442", buf[4:8])
	}
	for i := 20; i < 28; i++ {
		if buf[i] != 0xAB {
			t.Fatalf("payload byte %d mutated", i)
		}
	}
}

func TestWriteSTUNAttributes(t *testing.T) {
	// pad=48 → body=(48-20)&^3=28: XOR-MAPPED-ADDRESS(12) + SOFTWARE(4+12).
	pad := 48
	buf := make([]byte, pad+16)
	for i := pad; i < len(buf); i++ {
		buf[i] = byte(i) | 0x80
	}
	imitateFillPrefix(buf, pad, imitateSTUN)

	body := (pad - 20) &^ 0b11
	if int(binary.BigEndian.Uint16(buf[2:4])) != body {
		t.Errorf("advertised length = %d, want %d (== body, not overrun)", binary.BigEndian.Uint16(buf[2:4]), body)
	}
	if binary.BigEndian.Uint16(buf[20:22]) != 0x0020 {
		t.Errorf("attr 0 type = %#x, want 0x0020 XOR-MAPPED-ADDRESS", buf[20:22])
	}
	if binary.BigEndian.Uint16(buf[22:24]) != 8 {
		t.Errorf("XMA length = %d, want 8", binary.BigEndian.Uint16(buf[22:24]))
	}
	if buf[25] != 0x01 {
		t.Errorf("XMA family = %#x, want 0x01 IPv4", buf[25])
	}
	if binary.BigEndian.Uint16(buf[32:34]) != 0x8022 {
		t.Errorf("attr 1 type = %#x, want 0x8022 SOFTWARE", buf[32:34])
	}
	for i := pad; i < len(buf); i++ {
		if buf[i] != byte(i)|0x80 {
			t.Fatalf("payload byte %d mutated", i)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./device/ -run TestWriteSTUN -v`
Expected: FAIL — stub leaves zeroed bytes, type != 0x0101.

- [ ] **Step 3: Replace the `writeSTUN` stub**

Ensure `encoding/binary` is imported in `device/obf_imitate.go`. Replace `func writeSTUN(buf []byte, padding int, seed uint32) {}` with:

```go
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./device/ -run TestWriteSTUN -v`
Expected: PASS (both STUN tests).

- [ ] **Step 5: Commit**

```bash
git add device/obf_imitate.go device/obf_imitate_test.go
git commit -m "feat(imitate): STUN Binding Success Response writer"
```

---

### Task 4: DNS EDNS-OPT response writer (+ NULL fallback)

**Files:**
- Modify: `device/obf_imitate.go` (replace the `writeDNS` stub; add `writeDNSNull`, `writeDNSOptResponse`, `clampU16`, DNS constants)
- Test: `device/obf_imitate_test.go`

- [ ] **Step 1: Write the failing test**

Append to `device/obf_imitate_test.go`:

```go
func TestWriteDNSOptResponse(t *testing.T) {
	// pad=40 (>= 32): full EDNS OPT framing. total=46, OPT at byte 17.
	buf := make([]byte, 46)
	copy(buf[40:], []byte{0xBB, 0xCC, 0x01, 0x02, 0x03, 0x04})
	imitateFillPrefix(buf, 40, imitateDNS)

	if buf[0] != 0xBB || buf[1] != 0xCC {
		t.Errorf("TXID = %#x %#x, want from payload bytes 0xBB 0xCC", buf[0], buf[1])
	}
	if buf[2] != 0x81 || buf[3] != 0x80 {
		t.Errorf("flags = %#x %#x, want 0x81 0x80 (QR/RD/RA, NOERROR)", buf[2], buf[3])
	}
	if buf[10] != 0x00 || buf[11] != 0x01 {
		t.Errorf("ARCOUNT = %#x %#x, want 0x00 0x01", buf[10], buf[11])
	}
	if buf[18] != 0x00 || buf[19] != 0x29 {
		t.Errorf("OPT TYPE = %#x %#x, want 0x00 0x29 (41)", buf[18], buf[19])
	}
	// RDLENGTH covers to end: total(46) - 28 == 18.
	if got := binary.BigEndian.Uint16(buf[26:28]); got != 18 {
		t.Errorf("RDLENGTH = %d, want 18", got)
	}
	for i, b := range []byte{0xBB, 0xCC, 0x01, 0x02, 0x03, 0x04} {
		if buf[40+i] != b {
			t.Fatalf("payload byte %d mutated", 40+i)
		}
	}
}

func TestWriteDNSNullFallback(t *testing.T) {
	// pad=30 (< 32): legacy NULL record still covers the whole datagram.
	buf := make([]byte, 40)
	for i := 30; i < 40; i++ {
		buf[i] = 0xAB
	}
	imitateFillPrefix(buf, 30, imitateDNS)

	if buf[2] != 0x81 || buf[3] != 0x80 {
		t.Errorf("flags = %#x %#x, want 0x81 0x80", buf[2], buf[3])
	}
	if buf[18] != 0x00 || buf[19] != 0x0a {
		t.Errorf("answer TYPE = %#x %#x, want NULL (10)", buf[18], buf[19])
	}
	if got := binary.BigEndian.Uint16(buf[26:28]); int(got)+28 != 40 {
		t.Errorf("NULL RDLENGTH=%d; %d+28 != 40", got, got)
	}
	for i := 30; i < 40; i++ {
		if buf[i] != 0xAB {
			t.Fatalf("payload byte %d mutated", i)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./device/ -run TestWriteDNS -v`
Expected: FAIL — stub leaves zeroed bytes.

- [ ] **Step 3: Replace the `writeDNS` stub and add helpers**

Replace `func writeDNS(buf []byte, padding int, seed uint32) {}` with:

```go
const (
	dnsHeaderLen        = 12
	dnsRootQuestionLen  = 5
	dnsOptFixedLen      = 11
	dnsOptOptionHdrLen  = 4
	dnsOptMin           = dnsHeaderLen + dnsRootQuestionLen + dnsOptFixedLen + dnsOptOptionHdrLen // 32
	dnsOptUDPSize       = 1232
	dnsOptCoverCode     = 0xFDE9
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
	optOff := dnsHeaderLen + len(question) // 17 for a root question
	rdlength := clampU16(total - (optOff + dnsOptFixedLen))                     // total - 28
	optLen := clampU16(total - (optOff + dnsOptFixedLen + dnsOptOptionHdrLen))  // total - 32

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
		0x00,                                            // NAME: root label
		0x00, 0x29,                                      // TYPE OPT (41)
		byte(dnsOptUDPSize >> 8), byte(dnsOptUDPSize),   // CLASS = UDP size 1232
		0x00, 0x00, 0x00, 0x00,                          // TTL field 0
		byte(rdlength >> 8), byte(rdlength),             // RDLENGTH
		byte(dnsOptCoverCode >> 8), byte(dnsOptCoverCode), // OPTION-CODE 0xFDE9
		byte(optLen >> 8), byte(optLen),                 // OPTION-LENGTH
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./device/ -run TestWriteDNS -v`
Expected: PASS (both DNS tests).

- [ ] **Step 5: Commit**

```bash
git add device/obf_imitate.go device/obf_imitate_test.go
git commit -m "feat(imitate): DNS EDNS-OPT response writer with NULL fallback"
```

---

### Task 5: SIP response header-block writer

**Files:**
- Modify: `device/obf_imitate.go` (replace the `writeSIP` stub; add `decimalDigits`; add `fmt` import)
- Test: `device/obf_imitate_test.go`

- [ ] **Step 1: Write the failing test**

Append to `device/obf_imitate_test.go`:

```go
func TestWriteSIPResponse(t *testing.T) {
	// pad=150 fits a full header block (status line + mandatory headers + CRLFCRLF).
	pad := 150
	buf := make([]byte, pad+32)
	for i := pad; i < len(buf); i++ {
		buf[i] = 0xCC
	}
	imitateFillPrefix(buf, pad, imitateSIP)

	p := buf[:pad]
	if string(p[:8]) != "SIP/2.0 " {
		t.Errorf("status line prefix = %q, want %q", p[:8], "SIP/2.0 ")
	}
	// Header block ends with a blank line; body after it is space-filled.
	idx := indexOf(p, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatal("no header/body separator (\\r\\n\\r\\n) found")
	}
	for i := idx + 4; i < pad; i++ {
		if p[i] != ' ' {
			t.Fatalf("body byte %d = %#x, want space", i, p[i])
		}
	}
	for i := pad; i < len(buf); i++ {
		if buf[i] != 0xCC {
			t.Fatalf("payload byte %d mutated", i)
		}
	}
}

// indexOf is a tiny test helper (avoids importing bytes just for the test).
func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./device/ -run TestWriteSIP -v`
Expected: FAIL — stub leaves zeroed bytes, no `SIP/2.0 ` prefix.

- [ ] **Step 3: Replace the `writeSIP` stub and add `decimalDigits`**

Add `"fmt"` to the import block. Replace `func writeSIP(buf []byte, padding int, seed uint32) {}` with:

```go
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./device/ -run TestWriteSIP -v`
Expected: PASS.

- [ ] **Step 5: Run the whole package and commit**

Run: `go test ./device/ -run 'TestFnv1aSeed|TestLcgStep|TestWrite' -v`
Expected: PASS (all writer + PRNG tests).

```bash
git add device/obf_imitate.go device/obf_imitate_test.go
git commit -m "feat(imitate): SIP response header-block writer"
```

---

### Task 6: Byte-exact golden-vector fixture (Rust → Go)

This is the only check that actually enforces "byte-exact" — the structural tests above pass even on PRNG-extraction bugs (see review B1 / spec §7.6). One-time Rust generation, committed vectors, permanent Go cross-check.

**Files:**
- Modify: `../amneziawg-install/amneziawg-proxy/src/transform.rs` (add an `#[ignore]` dumper test)
- Create: `device/testdata/imitate_vectors.txt` (generated, committed)
- Test: `device/obf_imitate_golden_test.go`

- [ ] **Step 1: Add the Rust dumper test**

In `../amneziawg-install/amneziawg-proxy/src/transform.rs`, inside the existing `#[cfg(test)] mod tests { ... }` block (after `use super::*;`), add:

```rust
#[test]
#[ignore] // run explicitly: it writes a fixture for the Go port
fn dump_imitate_vectors() {
    use std::fmt::Write as _;
    let protos = [
        ("quic", Protocol::Quic),
        ("dns", Protocol::Dns),
        ("stun", Protocol::Stun),
        ("sip", Protocol::Sip),
    ];
    let payloads: [&[u8]; 4] = [
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        b"the quick brown fox jumps over the lazy dog!!",
        &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        &[0u8; 40],
    ];
    let pads = [10usize, 16, 20, 32, 40, 64, 150, 200];
    let mut out = String::new();
    for (pname, proto) in protos {
        for &payload in payloads.iter() {
            for &pad in pads.iter() {
                let mut data = vec![0u8; pad + payload.len()];
                data[pad..].copy_from_slice(payload);
                apply_padding(&mut data, pad, proto);
                let mut hex = String::new();
                for b in &data {
                    write!(hex, "{:02x}", b).unwrap();
                }
                let mut phex = String::new();
                for b in payload {
                    write!(phex, "{:02x}", b).unwrap();
                }
                writeln!(out, "{} {} {} {}", pname, pad, phex, hex).unwrap();
            }
        }
    }
    let path = std::env::var("IMITATE_VECTORS_OUT")
        .unwrap_or_else(|_| "imitate_vectors.txt".into());
    std::fs::write(&path, out).unwrap();
}
```

- [ ] **Step 2: Generate the fixture**

Run (from this repo root):

```bash
mkdir -p device/testdata
IMITATE_VECTORS_OUT="$PWD/device/testdata/imitate_vectors.txt" \
  cargo test --manifest-path ../amneziawg-install/amneziawg-proxy/Cargo.toml \
  dump_imitate_vectors -- --ignored --exact
```

Expected: cargo prints `test tests::dump_imitate_vectors ... ok`, and `device/testdata/imitate_vectors.txt` now has 128 lines (4 protos × 4 payloads × 8 pads). Sanity-check:

Run: `wc -l device/testdata/imitate_vectors.txt`
Expected: `128 device/testdata/imitate_vectors.txt`

> If cargo is unavailable in the environment, this task is the one place that needs it. Generate the fixture on a machine with the Rust toolchain and commit the resulting `.txt`; the Go cross-check (Step 3) then runs anywhere.

- [ ] **Step 3: Write the Go cross-check test**

Create `device/obf_imitate_golden_test.go`:

```go
package device

import (
	"bufio"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

func protoFromName(name string) (imitateProto, bool) {
	switch name {
	case "quic":
		return imitateQUIC, true
	case "dns":
		return imitateDNS, true
	case "stun":
		return imitateSTUN, true
	case "sip":
		return imitateSIP, true
	}
	return imitateNone, false
}

// TestImitateGoldenVectors enforces byte-exactness against transform.rs output.
// Each line: "<proto> <pad> <payload_hex> <output_hex>".
func TestImitateGoldenVectors(t *testing.T) {
	f, err := os.Open("testdata/imitate_vectors.txt")
	if err != nil {
		t.Fatalf("open fixture: %v (regenerate per Task 6 Step 2)", err)
	}
	defer f.Close()

	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			t.Fatalf("malformed fixture line: %q", line)
		}
		proto, ok := protoFromName(fields[0])
		if !ok {
			t.Fatalf("unknown proto %q", fields[0])
		}
		pad, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("bad pad %q: %v", fields[1], err)
		}
		payload, err := hex.DecodeString(fields[2])
		if err != nil {
			t.Fatalf("bad payload hex: %v", err)
		}
		want, err := hex.DecodeString(fields[3])
		if err != nil {
			t.Fatalf("bad output hex: %v", err)
		}

		buf := make([]byte, pad+len(payload))
		copy(buf[pad:], payload)
		imitateFillPrefix(buf, pad, proto)

		if hex.EncodeToString(buf) != hex.EncodeToString(want) {
			t.Errorf("%s pad=%d: byte mismatch\n got %x\nwant %x", fields[0], pad, buf, want)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no vectors loaded")
	}
	t.Logf("verified %d golden vectors", n)
}
```

- [ ] **Step 4: Run the cross-check**

Run: `go test ./device/ -run TestImitateGoldenVectors -v`
Expected: PASS, logs `verified 128 golden vectors`. If it FAILS, a writer diverged from `transform.rs` — check the §7.6 porter traps (byte extraction `>>16`, BE headers, LCG draw order, uint32 wrap).

- [ ] **Step 5: Commit**

```bash
git add device/testdata/imitate_vectors.txt device/obf_imitate_golden_test.go
git commit -m "test(imitate): byte-exact golden vectors from transform.rs"
```

The Rust dumper test lives in the separate `amneziawg-proxy` repo — commit it there separately (it is not part of this repo's tree).

---

### Task 7: Device state + `imitate_protocol` UAPI key

**Files:**
- Modify: `device/device.go` (add `imitate` field to the config cluster, ~`:113` after `ipackets`)
- Modify: `device/obf_imitate.go` (add `deviceImitate` type + `parseImitateProto`)
- Modify: `device/uapi.go` (add the `imitate_protocol` case after `s4`, ~`:385`)
- Test: `device/obf_imitate_test.go`

- [ ] **Step 1: Write the failing test for `parseImitateProto`**

Append to `device/obf_imitate_test.go`:

```go
func TestParseImitateProto(t *testing.T) {
	cases := map[string]imitateProto{
		"":     imitateNone,
		"none": imitateNone,
		"quic": imitateQUIC,
		"dns":  imitateDNS,
		"stun": imitateSTUN,
		"sip":  imitateSIP,
	}
	for in, want := range cases {
		got, err := parseImitateProto(in)
		if err != nil || got != want {
			t.Errorf("parseImitateProto(%q) = (%d,%v), want (%d,nil)", in, got, err, want)
		}
	}
	if _, err := parseImitateProto("ftp"); err == nil {
		t.Error("parseImitateProto(\"ftp\") should error")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./device/ -run TestParseImitateProto -v`
Expected: FAIL — `undefined: parseImitateProto`.

- [ ] **Step 3: Add `deviceImitate` and `parseImitateProto`**

Append to `device/obf_imitate.go` (add `"fmt"` and `"sync/atomic"` to imports if not already present):

```go
// deviceImitate is the device-level imitation config. proto is stored via UAPI
// under ipcMutex and read lock-free on the send path (atomic.Uint32), matching
// the existing lock-free paddings/junk reads. The Tier-4 fields are placeholders.
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
```

- [ ] **Step 4: Add the `imitate` field to the Device struct**

In `device/device.go`, change the config cluster (the `ipackets [5]*obfChain` line is the last field before the closing `}` of the struct):

```go
	ipackets [5]*obfChain

	imitate deviceImitate
}
```

- [ ] **Step 5: Add the UAPI case**

In `device/uapi.go`, immediately after the `case "s4":` block (which ends with `device.paddings.transport = padding`) and before `case "h1":`, insert:

```go
	case "imitate_protocol":
		proto, err := parseImitateProto(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse imitate_protocol: %w", err)
		}
		device.log.Verbosef("UAPI: Updating imitate protocol")
		device.imitate.proto.Store(uint32(proto))
```

- [ ] **Step 6: Write the UAPI parse integration test**

Create `device/uapi_test.go`:

```go
package device

import "testing"

func TestUAPIImitateProtocol(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	if err := dev.IpcSet("imitate_protocol=quic\n"); err != nil {
		t.Fatalf("set imitate_protocol=quic: %v", err)
	}
	if got := imitateProto(dev.imitate.proto.Load()); got != imitateQUIC {
		t.Errorf("proto = %d, want imitateQUIC(%d)", got, imitateQUIC)
	}

	if err := dev.IpcSet("imitate_protocol=ftp\n"); err == nil {
		t.Error("imitate_protocol=ftp should be rejected")
	}
}
```

Note: `randDevice` is an existing test helper in `device/device_test.go`. If its signature differs, mirror how `TestConfig`/`TestAWGDevicePing` construct a device in this package.

- [ ] **Step 7: Run the tests**

Run: `go test ./device/ -run 'TestParseImitateProto|TestUAPIImitateProtocol' -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add device/obf_imitate.go device/device.go device/uapi.go device/obf_imitate_test.go device/uapi_test.go
git commit -m "feat(imitate): deviceImitate state and imitate_protocol UAPI key"
```

---

### Task 8: Wire the four S-padding send sites through `fillPadding`

**Files:**
- Modify: `device/obf_imitate.go` (add the `fillPadding` helper)
- Modify: `device/send.go` (4 sites: ~`:161`, ~`:209`, ~`:246`, ~`:578`)
- Test: `device/device_test.go` (extend `TestAWGDevicePing`-style coverage) — or a new case in `device/uapi_test.go`

- [ ] **Step 1: Add the `fillPadding` helper**

Append to `device/obf_imitate.go`:

```go
// fillPadding rewrites buf[:padding] — protocol-conformant filler when an imitate
// protocol is configured, otherwise the original random padding. Read of proto is
// lock-free (atomic), never the config lock (see spec §8).
func (device *Device) fillPadding(buf []byte, padding int) {
	if p := imitateProto(device.imitate.proto.Load()); p != imitateNone {
		imitateFillPrefix(buf, padding, p)
	} else {
		rand.Read(buf[:padding])
	}
}
```

Add `"crypto/rand"` to the `device/obf_imitate.go` import block (the helper now uses it).

- [ ] **Step 2: Swap the handshake-init site (`device/send.go` ~:161)**

Replace:

```go
	if padding := peer.device.paddings.init; padding > 0 {
		buf := make([]byte, padding+len(packet))
		rand.Read(buf[:padding])
		copy(buf[padding:], packet)
		packet = buf
	}
```

with:

```go
	if padding := peer.device.paddings.init; padding > 0 {
		buf := make([]byte, padding+len(packet))
		copy(buf[padding:], packet)
		peer.device.fillPadding(buf, padding)
		packet = buf
	}
```

(Note: `copy` now precedes `fillPadding`, because the DNS/STUN/SIP writers seed from `buf[padding:]` — the payload must be in place first.)

- [ ] **Step 3: Swap the handshake-response site (`device/send.go` ~:209)**

Replace the identical `paddings.response` block the same way:

```go
	if padding := peer.device.paddings.response; padding > 0 {
		buf := make([]byte, padding+len(packet))
		copy(buf[padding:], packet)
		peer.device.fillPadding(buf, padding)
		packet = buf
	}
```

- [ ] **Step 4: Swap the cookie-reply site (`device/send.go` ~:246)**

Here the receiver variable is `device`, not `peer.device`:

```go
	if padding := device.paddings.cookie; padding > 0 {
		buf := make([]byte, padding+len(packet))
		copy(buf[padding:], packet)
		device.fillPadding(buf, padding)
		packet = buf
	}
```

- [ ] **Step 5: Swap the transport/keepalive site (`device/send.go` ~:578)**

This site shifts in place inside `elem.buffer` (it does not allocate a fresh buf). The payload (`elem.packet`) is already shifted to `elem.buffer[padding:]` by the copy loop before the fill, so ordering is already correct. Replace only the `rand.Read` line:

```go
			if padding := device.paddings.transport; padding > 0 {
				// elem.packet is stored at the start of elem.buffer
				// with zero padding
				for i := len(elem.packet) - 1; i >= 0; i-- {
					elem.buffer[i+padding] = elem.buffer[i]
				}
				device.fillPadding(elem.buffer[:], padding)
				elem.packet = elem.buffer[:padding+len(elem.packet)]
			}
```

> `elem.buffer` is a fixed-size array field; `elem.buffer[:]` gives the full slice. `fillPadding` reads `elem.buffer[padding:]` as the seed — that region holds the just-shifted real packet plus trailing zeros, exactly as `rand.Read` left the prefix before. Length is unchanged: `elem.packet` is re-sliced to `padding+len(packet)` as before.

- [ ] **Step 6: Add an end-to-end ping test with imitation enabled**

In `device/uapi_test.go`, add a test that brings up a patched↔patched pair with `imitate_protocol=quic` and passes traffic. Reuse the existing harness from `TestAWGDevicePing` (`device/device_test.go`) — copy its two-device setup and add `imitate_protocol=quic\n` to **both** `IpcSet` config strings, then run the same ping assertion. Concretely, locate `func TestAWGDevicePing` and model the new test on it:

```go
func TestAWGDevicePingImitateQUIC(t *testing.T) {
	// Identical to TestAWGDevicePing but both peers also set imitate_protocol=quic.
	// Asserts the tunnel still establishes and passes traffic — the anchor test
	// that the cosmetic rewrite is wire-compatible (here, patched <-> patched).
	t.Skip("fill in by cloning TestAWGDevicePing's setup + `imitate_protocol=quic` on both peers")
}
```

Then implement it by cloning the body of `TestAWGDevicePing` and appending `imitate_protocol=quic\n` to each peer's UAPI config (remove the `t.Skip`). Run the existing test first to see the exact harness:

Run: `go test ./device/ -run TestAWGDevicePing -v`
Expected: PASS (baseline harness works) — then mirror it.

- [ ] **Step 7: Run the full device test suite**

Run: `go test ./device/ -v`
Expected: PASS, including `TestImitateGoldenVectors`, `TestUAPIImitateProtocol`, and the new ping test.

- [ ] **Step 8: Commit**

```bash
git add device/obf_imitate.go device/send.go device/uapi_test.go
git commit -m "feat(imitate): route S-padding sites through fillPadding"
```

---

### Task 9: Full verification & wrap-up

**Files:** none (verification only)

- [ ] **Step 1: Build with version generation**

Run: `make`
Expected: builds `amneziawg-go` with no errors.

- [ ] **Step 2: Run the entire test suite (includes the gofmt gate)**

Run: `go test ./...`
Expected: PASS across all packages. `TestFormatting` must pass — if it fails, run `gofmt -w device/obf_imitate.go device/*_test.go` and re-run.

- [ ] **Step 3: Confirm default-off behavior is untouched**

Run: `go test ./device/ -run TestAWGDevicePing -v`
Expected: PASS — the baseline (no `imitate_protocol`) still uses `rand.Read`, proving backward compatibility.

- [ ] **Step 4: Optional — netns interop anchor (Linux, root)**

If a Linux/root environment is available, build and run the namespace tests to confirm a patched binary interops with a vanilla peer:

Run: `sudo ./tests/netns.sh ./amneziawg-go`
Expected: tunnel establishes, traffic passes. (Skip if not on Linux/root; the Go ping test in Task 8 is the in-process anchor.)

- [ ] **Step 5: Final review & summary commit (if any cleanup)**

Confirm `git log --oneline` shows the Tier-1 sequence. Tier 1 is complete: `obf_imitate.go` byte-exact port, golden fixture, `imitate_protocol` UAPI key, and the four S-padding sites shaped. Junk (Tier 2), I-packets (Tier 3), and `Id`/`Ib` (Tier 4) are separate plans.

---

## Self-Review

**Spec coverage (Tier 1 scope per spec §6):**
- `obf_imitate.go` PRNG + 4 writers byte-exact → Tasks 1–5. ✓
- `imitateProto` type + guarded `imitateFillPrefix` → Task 1. ✓
- Golden-byte fixture (spec §9 B1) → Task 6. ✓
- `imitate_protocol` UAPI key + `deviceImitate` (atomic, lock-free read — spec §8 / A2) → Task 7. ✓
- `fillPadding` helper + 4 S-padding swaps incl. keepalive/in-place transport site (spec §5 / B2) → Task 8. ✓
- DNS echo param dropped (B3) → Task 4 (`writeDNS` no-echo only). ✓
- Porter traps (spec §7.6) called out inline in Tasks 2–6 and the golden test. ✓
- Out of scope (correctly deferred): `imitateFillWhole`, junk shaping, I-packet builders, Tier 4. ✓

**Placeholder scan:** The only intentional skeleton is Task 8 Step 6's `t.Skip` clone-target, with explicit instructions to clone `TestAWGDevicePing` — necessary because the exact harness lives in existing code the executor must read. No "TBD"/"add error handling"/"similar to" placeholders elsewhere; all writer code is complete.

**Type consistency:** `imitateProto` consts vs `write*` function names (no collision); `imitateFillPrefix(buf, padding, p)` and `imitateFill(buf, padding, seed, p)` signatures consistent across Tasks 1/8; `deviceImitate.proto atomic.Uint32` stored as `uint32(proto)` (Task 7) and loaded as `imitateProto(...Load())` (Tasks 7/8) consistently; `fillPadding(buf, padding)` called on both `peer.device` and `device` receivers (Task 8) matching the helper's `*Device` receiver.
