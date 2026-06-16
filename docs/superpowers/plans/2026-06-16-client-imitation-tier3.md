# Client Imitation Tier 3 (I-packets + selector) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make AmneziaWG I-packets (`i1`–`i5`) shapeable as protocol-conformant QUIC/DNS/STUN/SIP datagrams via a new `imitateObf` adapter, completing mechanism C of the client-side traffic-imitation design.

**Architecture:** I-packets are sent through the existing `obf`/`obfChain` registry (`device/obf.go`, invoked at `device/send.go:131-137`). Tier 3 adds one new `obf` implementation — `imitateObf` — that mirrors `randObf` (`device/obf_rand.go`) but, instead of `rand.Read`, calls the Tier 2 `imitateFillWhole(buf, seed, proto)` whole-datagram filler. A single closure `newImitateObf(proto)` is registered four times in `obfBuilders` under the tags `q`/`dns`/`stun`/`sip`, so a config writes `i1=<q 600>`. The adapter injects a varying per-packet seed (an atomic counter, like `fillJunk`) so a chain of I-packets is not byte-identical. No new fill path and no new golden vectors: `imitateFillWhole` and its writers are already byte-exact-locked by `TestImitateGoldenVectors` (Tier 2).

**Tech Stack:** Go 1.24.4, no CGO. Files under `device/`. Tests via `go test ./device`.

**Out of scope (Tier 4, §7.5 of the spec):** the `imitate_sni` / `imitate_fingerprint` keys and the crafted long-header QUIC Initial + uTLS ClientHello. Tier 3 only reuses the existing same-length whole-datagram writers behind the I-packet path.

---

## File Structure

- **Create** `device/obf_imitate_obf.go` — the `imitateObf` type + `newImitateObf` builder. Kept in its own file (parallel to `obf_rand.go`, `obf_bytes.go`, …) so the obf-registry adapter is separate from the protocol writers in `obf_imitate.go`. Carries the `// SPDX-License-Identifier: MIT` header.
- **Create** `device/obf_imitate_obf_test.go` — unit tests for the adapter and registry wiring.
- **Modify** `device/obf.go:11-20` — register `q`/`dns`/`stun`/`sip` in `obfBuilders`.
- **Modify** `CLAUDE.md` — document the I-packet imitation tags under the imitation runtime note.

---

## Task 1: `imitateObf` adapter + `newImitateObf` builder

**Files:**
- Create: `device/obf_imitate_obf.go`
- Test: `device/obf_imitate_obf_test.go`

- [ ] **Step 1: Write the failing test**

Create `device/obf_imitate_obf_test.go`:

```go
// SPDX-License-Identifier: MIT

package device

import "testing"

func TestImitateObfBuilder(t *testing.T) {
	o, err := newImitateObf(imitateQUIC)("600")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := o.ObfuscatedLen(0); got != 600 {
		t.Errorf("ObfuscatedLen(0) = %d, want 600", got)
	}
	if got := o.DeobfuscatedLen(600); got != 0 {
		t.Errorf("DeobfuscatedLen(600) = %d, want 0 (cosmetic, carries no payload)", got)
	}
	if !o.Deobfuscate(nil, nil) {
		t.Error("Deobfuscate should always accept (cosmetic, like randObf)")
	}
	if _, err := newImitateObf(imitateQUIC)("notanumber"); err == nil {
		t.Error("non-numeric length must be rejected")
	}
}

func TestImitateObfObfuscateQUIC(t *testing.T) {
	o, err := newImitateObf(imitateQUIC)("600")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	buf := make([]byte, 600)
	o.Obfuscate(buf, nil)
	// QUIC 1-RTT short header: form bit 0, fixed bit 1, reserved bits 0
	// => (buf[0] & 0xC0) == 0x40. (Matches writeQUICShort / the golden writer.)
	if buf[0]&0xC0 != 0x40 {
		t.Errorf("first byte = %#x, want short-header form (0x40 | …)", buf[0])
	}
}

func TestImitateObfConsecutiveDiffer(t *testing.T) {
	o, err := newImitateObf(imitateQUIC)("600")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	a := make([]byte, 600)
	b := make([]byte, 600)
	o.Obfuscate(a, nil)
	o.Obfuscate(b, nil)
	if string(a) == string(b) {
		t.Error("consecutive I-packets are byte-identical; counter seed not advancing (A1 failure mode)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./device -run TestImitateObf -v`
Expected: FAIL — `undefined: newImitateObf`.

- [ ] **Step 3: Write minimal implementation**

Create `device/obf_imitate_obf.go`:

```go
// SPDX-License-Identifier: MIT

package device

import (
	"strconv"
	"sync/atomic"
)

// imitateObf is the obf-registry adapter for mechanism C (I-packets). It fills an
// entire I-packet datagram with protocol-conformant filler via imitateFillWhole,
// parallel to randObf (device/obf_rand.go) but protocol-shaped instead of random.
// Registered in obfBuilders as q/dns/stun/sip, configured e.g. as i1=<q 600>.
//
// Like randObf it is cosmetic on the wire: Deobfuscate is a no-op accept and
// DeobfuscatedLen is 0, so the I-packet carries no real payload and a vanilla peer
// drops it as undecryptable junk — exactly today's randObf behavior.
type imitateObf struct {
	length  int
	proto   imitateProto
	counter atomic.Uint64 // per-packet seed source; .Add(1) so consecutive I-packets differ
}

// newImitateObf returns an obfBuilder bound to proto. The builder parses the
// I-packet length from the tag value (<q 600> => length 600), matching randObf's
// "<r N>" length syntax. The same *imitateObf may be invoked concurrently for
// multiple peers' handshakes, so the seed counter is atomic.
func newImitateObf(proto imitateProto) obfBuilder {
	return func(val string) (obf, error) {
		length, err := strconv.Atoi(val)
		if err != nil {
			return nil, err
		}
		return &imitateObf{length: length, proto: proto}, nil
	}
}

func (o *imitateObf) Obfuscate(dst, src []byte) {
	seed := imitateJunkSeed(o.counter.Add(1))
	imitateFillWhole(dst[:o.length], seed, o.proto)
}

func (o *imitateObf) Deobfuscate(dst, src []byte) bool {
	// Cosmetic filler; nothing to validate (mirrors randObf).
	return true
}

func (o *imitateObf) ObfuscatedLen(n int) int { return o.length }

func (o *imitateObf) DeobfuscatedLen(n int) int { return 0 }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./device -run TestImitateObf -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add device/obf_imitate_obf.go device/obf_imitate_obf_test.go
git commit -m "feat(imitate): imitateObf I-packet adapter over imitateFillWhole (Tier 3)"
```

---

## Task 2: Register `q`/`dns`/`stun`/`sip` in `obfBuilders`

**Files:**
- Modify: `device/obf.go:11-20`
- Test: `device/obf_imitate_obf_test.go` (append)

- [ ] **Step 1: Write the failing test**

Append to `device/obf_imitate_obf_test.go`:

```go
func TestObfChainImitateRegistered(t *testing.T) {
	cases := []struct {
		tag   string
		proto imitateProto
	}{
		{"q", imitateQUIC},
		{"dns", imitateDNS},
		{"stun", imitateSTUN},
		{"sip", imitateSIP},
	}
	for _, c := range cases {
		spec := "<" + c.tag + " 600>"
		chain, err := newObfChain(spec)
		if err != nil {
			t.Fatalf("%s: newObfChain(%q): %v", c.tag, spec, err)
		}
		if got := chain.ObfuscatedLen(0); got != 600 {
			t.Errorf("%s: ObfuscatedLen(0) = %d, want 600", c.tag, got)
		}
		buf := make([]byte, chain.ObfuscatedLen(0))
		chain.Obfuscate(buf, nil) // must not panic; fills the whole datagram
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./device -run TestObfChainImitateRegistered -v`
Expected: FAIL — `newObfChain` joins errors `unknown tag <q>`, `unknown tag <dns>`, etc.

- [ ] **Step 3: Add the registry entries**

In `device/obf.go`, extend the `obfBuilders` map:

```go
var obfBuilders = map[string]obfBuilder{
	"b":  newBytesObf,
	"t":  newTimestampObf,
	"r":  newRandObf,
	"rc": newRandCharObf,
	"rd": newRandDigitsObf,
	"d":  newDataObf,
	"ds": newDataStringObf,
	"dz": newDataSizeObf,

	// Tier 3 traffic-imitation I-packets (mechanism C): protocol-shaped junk.
	"q":    newImitateObf(imitateQUIC),
	"dns":  newImitateObf(imitateDNS),
	"stun": newImitateObf(imitateSTUN),
	"sip":  newImitateObf(imitateSIP),
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./device -run TestObfChainImitateRegistered -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add device/obf.go device/obf_imitate_obf_test.go
git commit -m "feat(imitate): register q/dns/stun/sip I-packet obf builders (Tier 3)"
```

---

## Task 3: UAPI + integration coverage for imitation I-packets

**Files:**
- Test: `device/uapi_test.go` (append), `device/device_test.go` (append)

- [ ] **Step 1: Write the failing UAPI test**

Append to `device/uapi_test.go`. It builds its imitate test device with `randDevice(t)` (see `TestUAPIImitateProtocol` at `device/uapi_test.go:8-10`); use the same helper:

```go
func TestIpcSetImitateIPacket(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	if err := dev.IpcSet("i1=<q 600>\n"); err != nil {
		t.Fatalf("set i1=<q 600>: %v", err)
	}
	if dev.ipackets[0] == nil {
		t.Fatal("ipackets[0] not set after i1=<q 600>")
	}
	if got := dev.ipackets[0].ObfuscatedLen(0); got != 600 {
		t.Errorf("i1 ObfuscatedLen(0) = %d, want 600", got)
	}

	if err := dev.IpcSet("i2=<q notanumber>\n"); err == nil {
		t.Error("i2=<q notanumber> should be rejected (bad length)")
	}
}
```

> `randDevice(t)` is the existing test-device constructor used throughout `device/` tests (it sets up a configured `*Device`). `IpcSet` accepts the I-packet line directly. No new helper needed.

- [ ] **Step 2: Run the UAPI test to verify it fails**

Run: `go test ./device -run TestIpcSetImitateIPacket -v`
Expected: FAIL before Tasks 1–2 are present; with them present it should already PASS (this task only adds coverage). If it PASSES immediately, that is the intended state — continue.

- [ ] **Step 3: Add an end-to-end device test (patched sender ↔ vanilla peer)**

Append to `device/device_test.go`, mirroring `TestAWGDevicePingImitateQUIC` (`device/device_test.go:253`) but driving the imitation through an I-packet rather than `imitate_protocol`:

```go
func TestAWGDevicePingImitateIPacket(t *testing.T) {
	goroutineLeakCheck(t)

	pair := genTestPair(t, true,
		"h1", "123456-123500",
		"h2", "67543-67550",
		"h3", "123123-123200",
		"h4", "32345-32350",
		"i1", "<q 600>",
		"i2", "<dns 600>",
	)
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}
```

> Re-read `device/device_test.go:253-276` first and match its `genTestPair` signature and h1–h4 values exactly; only the `i1`/`i2` lines replace the `imitate_protocol` line. The I-packets are cosmetic junk the vanilla peer drops, so traffic must still pass — that is the interop assertion.

- [ ] **Step 4: Run the device test to verify it passes**

Run: `go test ./device -run TestAWGDevicePingImitateIPacket -v`
Expected: PASS. (If a pre-existing `-race` flake appears as it does for `TestAWGDevicePingImitateQUIC`, re-run that single test with `-race=false` per the existing comment near it.)

- [ ] **Step 5: Commit**

```bash
git add device/uapi_test.go device/device_test.go
git commit -m "test(imitate): UAPI + interop coverage for imitation I-packets (Tier 3)"
```

---

## Task 4: Document the I-packet imitation tags

**Files:**
- Modify: `CLAUDE.md` (the "Traffic imitation" runtime-gotchas bullet)

- [ ] **Step 1: Update the imitation note**

In `CLAUDE.md`, find the "Traffic imitation" bullet and append a sentence after the existing `imitate_protocol` description:

```markdown
  Tier 3 also exposes the same four shapes as I-packet builders in the AWG obf
  registry: `i1=<q LEN>` / `<dns LEN>` / `<stun LEN>` / `<sip LEN>` emit a single
  protocol-shaped fake datagram of `LEN` bytes (mechanism C, via `imitateObf` in
  `device/obf_imitate_obf.go` over `imitateFillWhole`); they are cosmetic junk a
  vanilla peer drops, seeded by a per-packet counter so a chain is not byte-identical.
```

- [ ] **Step 2: Verify formatting**

Run: `gofmt -l device/`
Expected: no output (no unformatted Go files).

- [ ] **Step 3: Run the full device test suite (includes the gofmt gate)**

Run: `go test ./device`
Expected: PASS, including `TestFormatting` and `TestImitateGoldenVectors` (unchanged — Tier 3 adds no new fill path).

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(imitate): document I-packet imitation tags (Tier 3)"
```

---

## Self-Review

**Spec coverage (§6 "Tier 3 — I-packets + selector"):**
- "Register `q`/`dns`/`stun`/`sip` builders" → Task 2. ✓
- The `imitateObf` adapter (§4 "The `imitateObf` adapter (mechanism C)") with injected varying seed (review A1) → Task 1. ✓
- "Finalize the device-level selector across all mechanisms" → the device selector (`imitate_protocol` → `fillPadding`/`fillJunk`) was completed in Tiers 1–2; I-packets use the per-tag selector (`q`/`dns`/`stun`/`sip`), which is the design's explicit mechanism-C selector (spec §4: "One builder per protocol"). With Task 2 all three mechanisms (A: S-padding, B: junk, C: I-packets) are wired. Documented in Task 4. ✓
- Mechanism C call site `device/obf_rand.go:24` / `send.go:131-137` — `imitateObf` sits beside `randObf`, additive via the registry, `randObf` unmodified (spec §4 "`randObf` is **not** modified"). ✓

**No new golden vectors:** `imitateObf.Obfuscate` delegates to `imitateFillWhole`, already byte-exact-locked by `TestImitateGoldenVectors` (Tier 2). The adapter adds only the seed-injection + length plumbing, covered by Task 1/3 unit tests. Stated in the Architecture header.

**Type consistency:** `newImitateObf(proto imitateProto) obfBuilder`, `imitateObf{length int; proto imitateProto; counter atomic.Uint64}`, `Obfuscate/Deobfuscate/ObfuscatedLen/DeobfuscatedLen` match the `obf` interface in `device/obf.go:22-27`. `imitateFillWhole(buf []byte, seed uint32, p imitateProto)` and `imitateJunkSeed(n uint64) uint32` match their Tier 2 definitions in `device/obf_imitate.go`. Tag keys `q`/`dns`/`stun`/`sip` match `i1=<q 600>` usage in Tasks 2–4.

**Concurrency:** `counter atomic.Uint64` — `SendHandshakeInitiation` (`send.go:131`) can run for multiple peers concurrently over the shared `device.ipackets` `*imitateObf`, so the per-packet seed increment must be atomic; mirrors `deviceImitate.junkCounter` (Tier 2).
