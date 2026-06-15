# Client Imitation Tier 2 (Junk Shaping) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Shape the `Jc` junk packets (currently raw `rand.Read`) into the configured imitation protocol, closing the layer-3 flow asymmetry the sidecar proxy can't (it returns `None` from `classify_awg_packet` for junk).

**Architecture:** Junk datagrams are *entirely fake* — no real ciphertext tail to seed from and no header offset to preserve. So Tier 2 adds the second entry point the design always called for: `imitateFillWhole(buf, seed, p)` — no no-op guard (we *want* `padding == len(buf)`), seed *injected* by the caller (a device counter), fills the entire buffer. A `Device.fillJunk` gate mirrors Tier 1's `fillPadding`, and the single junk `rand.Read` site in `send.go` routes through it. The protocol writers (`writeQUICShort`/`writeSTUN`/`writeSIP`) are reused unchanged because they are already pure functions of `(buf, padding, seed)`; only DNS needs surgery (see below).

**The DNS divergence (the one real design decision):** `writeDNS` derives its 2-byte TXID from `buf[padding:]` (the real payload), *ignoring* `seed`. In the whole-datagram path `buf[padding:]` is empty, so every DNS junk packet would be byte-identical `TXID=0x0000` + zero-filled OPT — the exact "A1 failure mode" §9.3 of the spec says to test against. QUIC/STUN/SIP all key off `seed` via the LCG and vary fine. **Resolution:** refactor DNS so the TXID is an explicit input (`writeDNSMsg(buf, padding, txid)`); the prefix path passes the payload-derived TXID (byte-exact, golden vectors unchanged), the whole path passes a seed-derived TXID. This is the documented structural divergence from `transform.rs` (which has no junk to shape), so it gets dedicated tests, not golden vectors.

**Seed source:** `junkCounter atomic.Uint64` on `deviceImitate`, `.Add(1)` per junk packet, run through `imitateJunkSeed(n) = fnv1aSeed(8 LE bytes of n)` so even counters 1,2,3 produce well-spread 32-bit LCG seeds (a raw small counter is a poor LCG seed and would leave the QUIC/STUN first bytes nearly constant).

**Tech Stack:** Go 1.24.4, `sync/atomic`, `encoding/binary`. Tests are standard `go test ./device`. Byte-exactness of the *prefix* path stays locked by the existing `TestImitateGoldenVectors`.

---

## File Structure

- `device/obf_imitate.go` — **modify.** Add `imitateFillWhole`, `imitateJunkSeed`, `writeDNSWhole`; refactor DNS into `writeDNSMsg` + TXID-parameterized `writeDNSNull`; add `junkCounter` to `deviceImitate`; add `Device.fillJunk`.
- `device/send.go` — **modify** one line (`:148`): `rand.Read(buf)` → `peer.device.fillJunk(buf)`.
- `device/obf_imitate_whole_test.go` — **create.** Unit tests for the whole-datagram path (no-guard, varies-with-seed for all four protocols incl. DNS, seed spreading, well-formedness, tiny-size safety).
- `device/obf_imitate_test.go` — **modify.** Nothing required; the DNS refactor must leave `TestWriteDNSOptResponse` / `TestWriteDNSNullFallback` passing unchanged (that's the regression proof).

No UAPI change: Tier 1's `imitate_protocol` key already drives all mechanisms; junk reads the same `imitate.proto`.

---

## Task 1: Refactor DNS to take an explicit TXID (no behavior change)

This is a pure refactor under the existing golden + structural tests — it must change *zero* bytes of output for the prefix path. Do it first so the whole-datagram DNS path in Task 3 can reuse the shared writer.

**Files:**
- Modify: `device/obf_imitate.go` (`writeDNS` ~`:237-259`, `writeDNSNull` ~`:300-352`)
- Test: existing `device/obf_imitate_test.go::TestWriteDNSOptResponse`, `::TestWriteDNSNullFallback`, `device/obf_imitate_golden_test.go::TestImitateGoldenVectors`

- [ ] **Step 1: Run the existing DNS + golden tests to capture the green baseline**

Run: `go test ./device -run 'TestWriteDNS|TestImitateGoldenVectors' -v`
Expected: PASS (`TestWriteDNSOptResponse`, `TestWriteDNSNullFallback`, `TestImitateGoldenVectors`).

- [ ] **Step 2: Extract TXID derivation out of `writeDNS`; add `writeDNSMsg`**

Replace the body of `writeDNS` (keep the `seed` param for the dispatcher signature; it stays unused on the prefix path) so it derives the TXID from the payload then delegates:

```go
// writeDNS emits an EDNS OPT-framed DNS response (no-echo path only — a client has
// no incoming query to echo). The TXID comes from the payload, not the PRNG seed,
// so `seed` is unused. Byte-exact port of transform.rs apply_dns_padding (echo=None).
func writeDNS(buf []byte, padding int, seed uint32) {
	_ = seed
	if padding == 0 {
		return
	}
	var txid [2]byte
	payload := buf[padding:]
	if len(payload) > 0 {
		txid[0] = payload[0]
	}
	if len(payload) > 1 {
		txid[1] = payload[1]
	}
	writeDNSMsg(buf, padding, txid)
}

// writeDNSMsg writes a DNS message into buf[:padding] with the given TXID, choosing
// the full EDNS OPT framing or the legacy NULL fallback by pad size. Shared by the
// prefix path (writeDNS, TXID from payload) and the whole-datagram junk path
// (writeDNSWhole, TXID from the injected seed).
func writeDNSMsg(buf []byte, padding int, txid [2]byte) {
	if padding < dnsOptMin {
		writeDNSNull(buf, padding, txid)
		return
	}
	total := len(buf)
	p := buf[:padding]
	question := []byte{0x00, 0x00, 0x01, 0x00, 0x01} // root QNAME + QTYPE A + QCLASS IN
	writeDNSOptResponse(p, total, txid, question)
}
```

- [ ] **Step 3: Change `writeDNSNull` to take the TXID as a parameter**

Replace the signature and drop its internal payload-based TXID derivation (the `total`/`p` locals stay; `payload` is no longer needed):

```go
// writeDNSNull is the legacy TYPE NULL fallback for padding < dnsOptMin.
// Byte-exact port of transform.rs apply_dns_padding_null. TXID is supplied by the
// caller (payload-derived on the prefix path, seed-derived on the junk path).
func writeDNSNull(buf []byte, padding int, txid [2]byte) {
	total := len(buf)
	p := buf[:padding]
	if len(p) == 0 {
		return
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
		txid[0], txid[1],
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

> Note: the old `writeDNSNull` read `payload[0]/[1]` into `txHi/txLo`. The new caller `writeDNS` passes exactly those same bytes as `txid`, so for the prefix path the emitted bytes are identical — that's what Step 4 proves.

- [ ] **Step 4: Run the DNS + golden tests to verify zero behavior change**

Run: `go test ./device -run 'TestWriteDNS|TestImitateGoldenVectors' -v`
Expected: PASS — identical to the Step 1 baseline. (`TestImitateGoldenVectors` passing is the byte-exactness proof; if any DNS vector now differs, the refactor changed output and must be fixed before proceeding.)

- [ ] **Step 5: Commit**

```bash
gofmt -w device/obf_imitate.go
git add device/obf_imitate.go
git commit -m "refactor(imitate): thread DNS TXID through an explicit param"
```

---

## Task 2: `imitateJunkSeed` — well-spread seed from the junk counter

**Files:**
- Modify: `device/obf_imitate.go`
- Test: `device/obf_imitate_whole_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `device/obf_imitate_whole_test.go`:

```go
package device

import (
	"encoding/binary"
	"testing"
)

func TestImitateJunkSeedSpreads(t *testing.T) {
	// Small consecutive counters must produce distinct, well-spread seeds — a raw
	// counter would leave the QUIC/STUN leading bytes nearly constant.
	seen := map[uint32]bool{}
	var prev uint32
	for n := uint64(1); n <= 8; n++ {
		s := imitateJunkSeed(n)
		if seen[s] {
			t.Fatalf("imitateJunkSeed(%d) = %#x collides with an earlier counter", n, s)
		}
		seen[s] = true
		if n > 1 && (s>>24) == (prev>>24) {
			t.Errorf("imitateJunkSeed top byte did not change between %d and %d (%#x vs %#x)", n-1, n, prev, s)
		}
		prev = s
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./device -run TestImitateJunkSeedSpreads -v`
Expected: FAIL — `undefined: imitateJunkSeed`.

- [ ] **Step 3: Implement `imitateJunkSeed`**

Add to `device/obf_imitate.go` (near `fnv1aSeed`):

```go
// imitateJunkSeed turns a monotonic junk counter into a well-spread 32-bit LCG
// seed by hashing its 8 little-endian bytes with FNV-1a. A raw counter is a poor
// LCG seed (small values leave the leading output bytes nearly constant); the hash
// decorrelates consecutive packets so a junk flow is not a sequence of near-clones.
func imitateJunkSeed(n uint64) uint32 {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return fnv1aSeed(b[:])
}
```

Add `"encoding/binary"` to the imports if not already present (it is, for the writers).

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./device -run TestImitateJunkSeedSpreads -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w device/obf_imitate.go device/obf_imitate_whole_test.go
git add device/obf_imitate.go device/obf_imitate_whole_test.go
git commit -m "feat(imitate): add imitateJunkSeed counter mixer"
```

---

## Task 3: `imitateFillWhole` + `writeDNSWhole` — the second entry point

**Files:**
- Modify: `device/obf_imitate.go`
- Test: `device/obf_imitate_whole_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `device/obf_imitate_whole_test.go`:

```go
// allProtos is the set that shapes junk (none is excluded — it never reaches fill).
var allProtos = []imitateProto{imitateQUIC, imitateDNS, imitateSTUN, imitateSIP}

func TestImitateFillWholeVariesWithSeed(t *testing.T) {
	// The A1 failure mode: two junk packets of the same size with different seeds
	// must differ — for EVERY protocol, DNS included.
	const n = 600
	for _, p := range allProtos {
		a := make([]byte, n)
		b := make([]byte, n)
		imitateFillWhole(a, imitateJunkSeed(1), p)
		imitateFillWhole(b, imitateJunkSeed(2), p)
		identical := true
		for i := 0; i < n; i++ {
			if a[i] != b[i] {
				identical = false
				break
			}
		}
		if identical {
			t.Errorf("proto %s: whole-datagram fill is byte-identical across seeds", imitateProtoName(p))
		}
	}
}

func TestImitateFillWholeWellFormed(t *testing.T) {
	const n = 600
	// QUIC: short-header first byte, form=0 fixed=1 reserved=00.
	q := make([]byte, n)
	imitateFillWhole(q, imitateJunkSeed(7), imitateQUIC)
	if q[0]&0xC0 != 0x40 {
		t.Errorf("QUIC byte0 = %#x, want high bits 0x40", q[0])
	}
	if q[0]&0x18 != 0x00 {
		t.Errorf("QUIC reserved bits = %#x, want 0", q[0]&0x18)
	}

	// DNS: full OPT framing, TXID from the seed (not 0x0000), TYPE OPT at 18..19.
	d := make([]byte, n)
	seed := imitateJunkSeed(7)
	imitateFillWhole(d, seed, imitateDNS)
	if d[0] != byte(seed>>8) || d[1] != byte(seed) {
		t.Errorf("DNS TXID = %#x %#x, want seed-derived %#x %#x", d[0], d[1], byte(seed>>8), byte(seed))
	}
	if d[2] != 0x81 || d[3] != 0x80 {
		t.Errorf("DNS flags = %#x %#x, want 0x81 0x80", d[2], d[3])
	}
	if d[18] != 0x00 || d[19] != 0x29 {
		t.Errorf("DNS OPT TYPE = %#x %#x, want 0x00 0x29", d[18], d[19])
	}

	// STUN: Binding Success Response, advertised length == body, magic cookie.
	s := make([]byte, n)
	imitateFillWhole(s, imitateJunkSeed(7), imitateSTUN)
	if binary.BigEndian.Uint16(s[0:2]) != 0x0101 {
		t.Errorf("STUN type = %#x, want 0x0101", s[0:2])
	}
	if binary.BigEndian.Uint32(s[4:8]) != 0x2112A442 {
		t.Errorf("STUN cookie = %#x, want 0x2112A442", s[4:8])
	}
	body := (n - 20) &^ 0b11
	if int(binary.BigEndian.Uint16(s[2:4])) != body {
		t.Errorf("STUN length = %d, want %d (== body)", binary.BigEndian.Uint16(s[2:4]), body)
	}

	// SIP: status line.
	sip := make([]byte, n)
	imitateFillWhole(sip, imitateJunkSeed(7), imitateSIP)
	if string(sip[:8]) != "SIP/2.0 " {
		t.Errorf("SIP status prefix = %q, want %q", sip[:8], "SIP/2.0 ")
	}
}

func TestImitateFillWholeTinySizesNoPanic(t *testing.T) {
	// Junk sizes are user-configured (jmin/jmax) and may be tiny. No writer may
	// panic or read out of bounds when padding == len(buf) is below a protocol min.
	for _, n := range []int{0, 1, 2, 5, 12, 20, 31, 32} {
		for _, p := range allProtos {
			buf := make([]byte, n)
			imitateFillWhole(buf, imitateJunkSeed(uint64(n)+1), p) // must not panic
			if len(buf) != n {
				t.Fatalf("proto %s size %d: length changed to %d", imitateProtoName(p), n, len(buf))
			}
		}
	}
}

func TestImitateFillWholeDNSNullForTinyPad(t *testing.T) {
	// pad < dnsOptMin (32) → NULL fallback, still seed-derived TXID, no panic.
	const n = 30
	seed := imitateJunkSeed(3)
	buf := make([]byte, n)
	imitateFillWhole(buf, seed, imitateDNS)
	if buf[0] != byte(seed>>8) || buf[1] != byte(seed) {
		t.Errorf("DNS NULL TXID = %#x %#x, want seed-derived", buf[0], buf[1])
	}
	if buf[18] != 0x00 || buf[19] != 0x0a {
		t.Errorf("DNS NULL answer TYPE = %#x %#x, want 0x00 0x0a (NULL)", buf[18], buf[19])
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./device -run 'TestImitateFillWhole' -v`
Expected: FAIL — `undefined: imitateFillWhole`.

- [ ] **Step 3: Implement `imitateFillWhole` and `writeDNSWhole`**

Add to `device/obf_imitate.go` (next to `imitateFillPrefix`):

```go
// imitateFillWhole writes a complete fake datagram of protocol p into the entire
// buf, seeded by the caller-supplied seed. Unlike imitateFillPrefix it has NO
// no-op guard: junk and I-packets WANT padding == len(buf). The seed is injected
// (not derived from buf, which carries no real payload here), so consecutive
// packets differ — see imitateJunkSeed. Used by Device.fillJunk (Tier 2) and the
// imitateObf adapter (Tier 3).
func imitateFillWhole(buf []byte, seed uint32, p imitateProto) {
	padding := len(buf)
	switch p {
	case imitateQUIC:
		writeQUICShort(buf, padding, seed)
	case imitateDNS:
		writeDNSWhole(buf, seed)
	case imitateSTUN:
		writeSTUN(buf, padding, seed)
	case imitateSIP:
		writeSIP(buf, padding, seed)
	}
}

// writeDNSWhole shapes an entire fake datagram as a DNS message. It diverges from
// transform.rs (which never shapes junk): there is no payload to source the TXID
// from, so the TXID is derived from the injected seed. Without this, every DNS
// junk packet would be byte-identical (TXID 0x0000 + zero-filled OPT) — the A1
// failure mode. Option-data/NULL rdata stay zero-filled, as the design notes.
func writeDNSWhole(buf []byte, seed uint32) {
	padding := len(buf)
	if padding == 0 {
		return
	}
	txid := [2]byte{byte(seed >> 8), byte(seed)}
	writeDNSMsg(buf, padding, txid)
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./device -run 'TestImitateFillWhole' -v`
Expected: PASS (all four sub-tests).

- [ ] **Step 5: Commit**

```bash
gofmt -w device/obf_imitate.go device/obf_imitate_whole_test.go
git add device/obf_imitate.go device/obf_imitate_whole_test.go
git commit -m "feat(imitate): add imitateFillWhole whole-datagram entry point"
```

---

## Task 4: `deviceImitate.junkCounter` + `Device.fillJunk` gate

**Files:**
- Modify: `device/obf_imitate.go` (`deviceImitate` struct ~`:26-28`, add `fillJunk` near `fillPadding` ~`:474`)
- Test: `device/obf_imitate_whole_test.go`

- [ ] **Step 1: Write the failing test**

Append to `device/obf_imitate_whole_test.go`:

```go
func TestFillJunkShapesWhenProtoSet(t *testing.T) {
	dev := &Device{}
	dev.imitate.proto.Store(uint32(imitateQUIC))

	// Each call must advance the counter so successive junk packets differ.
	a := make([]byte, 600)
	b := make([]byte, 600)
	dev.fillJunk(a)
	dev.fillJunk(b)

	if a[0]&0xC0 != 0x40 {
		t.Errorf("fillJunk QUIC byte0 = %#x, want high bits 0x40", a[0])
	}
	identical := true
	for i := range a {
		if a[i] != b[i] {
			identical = false
			break
		}
	}
	if identical {
		t.Fatal("consecutive fillJunk packets are byte-identical (counter not advancing)")
	}
}

func TestFillJunkNoneFillsBuffer(t *testing.T) {
	// proto == none → random fill of the whole buffer (length unchanged, not all-zero).
	dev := &Device{} // zero value: imitateNone
	buf := make([]byte, 64)
	dev.fillJunk(buf)
	if len(buf) != 64 {
		t.Fatalf("length changed to %d", len(buf))
	}
	allZero := true
	for _, x := range buf {
		if x != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("fillJunk(none) left the buffer all-zero; expected random fill")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./device -run 'TestFillJunk' -v`
Expected: FAIL — `dev.fillJunk undefined`.

- [ ] **Step 3: Add `junkCounter` and `fillJunk`**

In `device/obf_imitate.go`, extend the struct:

```go
type deviceImitate struct {
	proto       atomic.Uint32 // imitateProto
	junkCounter atomic.Uint64 // seeds whole-datagram junk fill (mechanism B); .Add(1) per packet
}
```

Add the gate next to `fillPadding`:

```go
// fillJunk fills an entire junk datagram. When an imitate protocol is configured
// it shapes the whole buffer as that protocol (mechanism B), seeded by a per-packet
// device counter so consecutive junk packets are not byte-identical; otherwise it
// falls back to the original random fill. Read of proto is lock-free (atomic),
// matching fillPadding and the existing junk/paddings reads.
func (device *Device) fillJunk(buf []byte) {
	if p := imitateProto(device.imitate.proto.Load()); p != imitateNone {
		seed := imitateJunkSeed(device.imitate.junkCounter.Add(1))
		imitateFillWhole(buf, seed, p)
	} else {
		rand.Read(buf)
	}
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./device -run 'TestFillJunk' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w device/obf_imitate.go device/obf_imitate_whole_test.go
git add device/obf_imitate.go device/obf_imitate_whole_test.go
git commit -m "feat(imitate): add fillJunk gate + junkCounter device state"
```

---

## Task 5: Wire the junk send site

**Files:**
- Modify: `device/send.go:148`

- [ ] **Step 1: Re-grep to confirm the line hasn't drifted**

Run: `grep -n 'rand.Read(buf)' device/send.go`
Expected: one hit inside the `jc` loop (`buf := make([]byte, n)` immediately above it). If the line number differs from 148, use the grep result.

- [ ] **Step 2: Replace the junk `rand.Read` with `fillJunk`**

In `device/send.go`, inside the junk loop:

```go
		buf := make([]byte, n)
		peer.device.fillJunk(buf)
		sendBuffer = append(sendBuffer, buf)
```

(Replaces `rand.Read(buf)` with `peer.device.fillJunk(buf)`. The `crypto/rand` import stays — it's still used by the `rand.Int` size draw just above and by `fillPadding`'s none-path.)

- [ ] **Step 3: Build to confirm it compiles**

Run: `go build ./...`
Expected: no output (success).

- [ ] **Step 4: Run the end-to-end imitate anchor**

`TestAWGDevicePingImitateQUIC` (`device/device_test.go:253`) already configures `jc=5` junk + `imitate_protocol=quic`, so it now exercises shaped junk through the real send path against a patched↔patched pair. Per its existing comment, run without the race detector:

Run: `go test ./device -run 'TestAWGDevicePingImitateQUIC' -count=1 -race=false -v`
Expected: PASS (both ping sub-tests). This proves shaped junk does not break the handshake/transport flow.

- [ ] **Step 5: Commit**

```bash
git add device/send.go
git commit -m "feat(imitate): route Jc junk packets through fillJunk (Tier 2)"
```

---

## Task 6: Full suite + formatting gate

**Files:** none (verification only)

- [ ] **Step 1: Run the whole device suite**

Run: `go test ./device -count=1`
Expected: PASS. (If a pre-existing race flake appears in `TestAWGDevicePingImitateQUIC` under the default `-race`, re-run that single test with `-race=false` per its comment; the new Tier 2 tests are race-clean.)

- [ ] **Step 2: Run the formatting gate across the module**

Run: `go test ./... -run TestFormatting`
Expected: PASS — `TestFormatting` fails the build on any non-gofmt'd file. If it fails, run `gofmt -w device/obf_imitate.go device/obf_imitate_whole_test.go device/send.go` and re-run.

- [ ] **Step 3: Build via make (regenerates version.go)**

Run: `make`
Expected: builds the binary with a correct version string.

- [ ] **Step 4: Final commit if gofmt changed anything**

```bash
git add -A
git commit -m "chore(imitate): gofmt Tier 2 sources" || echo "nothing to format"
```

---

## Self-Review

**Spec coverage (§ refs to the design spec):**
- §6 "Tier 2 — junk: wire `send.go:148` to device-counter-seeded full-datagram fill" → Tasks 4 (counter + gate) + 5 (wire). ✓
- §3 "`imitateFillWhole(buf, seed, p)` — NO guard, seed injected" → Task 3. ✓
- §3 seeding model "Junk (B): injected device counter seed, fill entire buffer (`padding == len(buf)`)" → Task 4 `fillJunk` + Task 3 `imitateFillWhole` uses `padding := len(buf)`. ✓
- §3 device state "`junkCounter atomic.Uint64`" → Task 4. ✓
- §5 Mechanism B "the one place the port diverges structurally from transform.rs → dedicated tests" → the DNS-TXID-from-seed divergence (Tasks 1+3) with `TestImitateFillWhole*` + `TestFillJunk*`. ✓
- §9.3 "assert consecutive packets are NOT byte-identical (the A1 failure mode), well-formed, `padding == len(buf)`" → `TestImitateFillWholeVariesWithSeed` (all 4 protos), `TestImitateFillWholeWellFormed`, `TestFillJunkShapesWhenProtoSet`. ✓
- §8/§4 backward compat "absent or none → rand.Read, identical to today" → `fillJunk` none-branch + `TestFillJunkNoneFillsBuffer`. ✓
- §7/§8 "tiny pads never panic, never length-drift" → `TestImitateFillWholeTinySizesNoPanic`, `TestImitateFillWholeDNSNullForTinyPad`. ✓
- §9.4 anchor "extend an imitate test as the patched↔patched anchor" → existing `TestAWGDevicePingImitateQUIC` now covers shaped junk (Task 5 Step 4). ✓
- §8 concurrency "proto read lock-free, junk counter atomic.Uint64, writers pure" → `fillJunk` uses `proto.Load()` + `junkCounter.Add(1)`; writers unchanged pure functions. ✓

**Placeholder scan:** none — every code step contains complete code; every run step has an exact command + expected result.

**Type consistency:** `imitateFillWhole(buf []byte, seed uint32, p imitateProto)`, `writeDNSWhole(buf []byte, seed uint32)`, `writeDNSMsg(buf []byte, padding int, txid [2]byte)`, `writeDNSNull(buf []byte, padding int, txid [2]byte)`, `imitateJunkSeed(n uint64) uint32`, `Device.fillJunk(buf []byte)`, `deviceImitate.junkCounter atomic.Uint64` — names and signatures match across Tasks 1–5. `writeDNS`/`writeQUICShort`/`writeSTUN`/`writeSIP` signatures are unchanged.

**Out of scope (deferred to Tier 3):** the `imitateObf` adapter and `q`/`dns`/`stun`/`sip` `obfBuilders` for I-packets. `imitateFillWhole` is built here so Tier 3 only adds the adapter, not a new fill path.
