# Review — Client-side traffic imitation design spec

**Reviews:** `docs/superpowers/specs/2026-06-15-client-side-traffic-imitation-design.md`
**Date:** 2026-06-15
**Method:** claims cross-checked against the actual `device/` code in this fork and against `amneziawg-install/amneziawg-proxy/src/transform.rs`. Line numbers below are ground-truth from this review (the spec's own numbers have drifted — see §C).

---

## Verdict

**Approve the architecture; fix two things before Tier 1, tighten three before merge.**

The core thesis holds up under inspection: the padding rewrite is genuinely cosmetic (the receiver never looks at padding content), so a sender-only, length-invariant patch that interops with a vanilla peer is the right shape. The additive `obf` registry is a clean fit for mechanism C, backward-compat via a zero-value `imitateNone` is sound, and the honest threat model (layer-3 only, nothing for statistical analysis) is a strength — keep it.

Two issues need to be resolved in the design before coding Tier 1/2, because they are not "implementation details" — they change the function signatures:

1. **Whole-datagram fill (mechanisms B and C) cannot reuse `apply_padding` as-is** — the `pad_size >= len` guard *and* the payload-self-seeding both break when `padding == len(buf)`. (§A1 — blocker.)
2. **The concurrency claim is wrong for this codebase** — `paddings`/`junk` are read lock-free on the hot send path; do not take the config lock per-packet. (§A2 — high.)

Everything else is small (§B/§C).

---

## What I verified (so the design can be trusted on these points)

| Spec claim | Status | Ground truth |
|---|---|---|
| Receiver size-matches and validates at offset `padding`, never inspects padding content | ✅ VERIFIED | `device/receive.go:570,582,594,606` size-match; `:572-573` `data := packet[padding:]; header.Validate(...)`. Padding bytes never read. |
| `obf` interface = `Obfuscate/Deobfuscate/ObfuscatedLen/DeobfuscatedLen`; `obfBuilders` string→builder registry | ✅ VERIFIED | `device/obf.go:9` `obfBuilder`, `:11-20` registry (`b t r rc rd d ds dz`), `:22-27` interface. |
| New `q/dns/stun/sip` builders are purely additive, `randObf` untouched | ✅ VERIFIED | All 8 `obf_*.go` follow the same pattern; adding a file + builder + map entry is the established idiom. |
| `randObf` fill + "no way to validate randomness" comment | ✅ VERIFIED | `device/obf_rand.go:24` `rand.Read`, `:28-29` comment. |
| I-packets emitted before handshake; parsed into `ipackets [5]*obfChain` | ✅ VERIFIED | send loop `device/send.go:131-137`; parse `device/uapi.go:415-448`; field `device/device.go:113`. |
| `jc/jmin/jmax/s1-s4` parsed in one UAPI switch under a config lock | ✅ VERIFIED | `device/uapi.go:310-385`; lock `:191-192` (`ipcMutex`, held for whole `IpcSetOperation`). A new `imitate_protocol` case slots cleanly after `s4` (`:385`). |
| Device config fields `junk`/`paddings`/`headers`/`ipackets` | ✅ VERIFIED | `device/device.go:93-97, 99-104, 106-111, 113`. |
| Unset/`none` → identical `rand.Read` behavior | ✅ VERIFIED | Zero-value `imitateProto(0) == imitateNone`; gate `if p != imitateNone` mirrors the existing `if padding > 0` idiom. |
| `transform.rs` PRNG, 4 writers, signatures, edge cases | ✅ VERIFIED byte-for-byte | FNV-1a `0x811c9dc5`/`0x01000193` over first 64 B (`transform.rs:192-200`); glibc LCG `*1103515245+12345` (`:722-725`); QUIC byte0, DNS `0x8180`/`0xFDE9`/`DNS_OPT_MIN=32`, STUN `0x0101`/`0x2112A442`/SOFTWARE-clamp-124, SIP header block — all as the spec describes. 41 `#[test]`s exist to mirror. |

Conclusion: the spec's reading of the codebase and of `transform.rs` is accurate. The findings below are about places where the *design* needs adjusting, not where it misread the code.

---

## A. Must-fix before implementing

### A1 — Whole-datagram fill needs its own seeded, unguarded entry point (blocker)

This is the one catch that the spec hand-waves ("the one place the port diverges structurally… → dedicated tests") without naming the actual conflict. Two distinct problems, same root:

1. **The guard.** `transform.rs:30-33` `apply_padding` returns a **no-op** when `pad_size == 0 || pad_size >= data.len()`. Mechanisms B (junk) and C (`imitateObf`) want to fill the *whole* buffer — i.e. `padding == len(buf)`. A "byte-exact port" of `apply_padding` therefore **no-ops on every junk and I-packet**, leaving them zero-filled. The spec's §3 signature `imitateFill(buf, padding, p)` plus "fill the entire buffer with `padding == len(buf)`" is in direct contradiction with the guard it claims to port verbatim.

2. **Self-seeding.** The Rust writers seed from `fnv1aSeed(payload)` where `payload = buf[padding:]`. When `padding == len(buf)` the payload slice is **empty**, so `fnv1aSeed([])` returns the bare FNV offset basis **every time** → every junk/I-packet is byte-identical. That defeats the point (a flow of identical "QUIC" packets is itself a signature). The spec's §3 "Seeding model" correctly says B seeds from a counter and C "delegates to the same writers" — but the `imitateFill(buf, padding, proto)` signature has **nowhere to inject that counter**; the writers self-seed internally.

**Fix (design-level, do this before Tier 1's signatures are frozen):** split the fill into two entry points.

```go
// Mechanism A: prefix on a real packet. Seed = payload after the padding.
// Keeps the pad_size>=len / pad_size==0 no-op guard (matches transform.rs).
func imitateFillPrefix(buf []byte, padding int, p imitateProto)   // seed = fnv1aSeed(buf[padding:])

// Mechanisms B & C: the whole datagram is fake. No guard. Seed injected.
func imitateFillWhole(buf []byte, seed uint32, p imitateProto)    // junk: seed from device counter; I-pkt: from its own counter
```

`imitateFillPrefix` is the byte-exact port. `imitateFillWhole` reuses the *protocol writers* (which already `split_at`/`split_at_mut` and accept an externally-derived seed) but skips the top-level guard and takes the seed as a parameter. Tier 1's `fillPadding` helper wraps `imitateFillPrefix`; Tiers 2/3 wrap `imitateFillWhole`. This also resolves the unspecified "what seeds mechanism C" gap.

> Note the realism cost (worth one honest line in the spec, consistent with its threat-model tone): a whole-datagram DNS/STUN/SIP fill has **empty** option-data/body (no trailing ciphertext to carry), and a junk flow of 1-RTT *short-header* QUIC packets with no preceding Initial doesn't resemble a connection opening. Fine for layer-3 protocol-positive checks; does nothing extra against a stateful parser — which is exactly what Tier 4 `Id`/`qinit` is for.

### A2 — Don't read config under a lock on the hot send path (high)

Spec §8: *"`proto` is read under the config lock (set rarely via UAPI)."* That contradicts how this codebase actually works. The existing hot-path reads are **lock-free**:

- `device/send.go:139-141` reads `peer.device.junk.{count,min,max}` with no lock.
- `:161, :209, :246, :578` read `device.paddings.*` with no lock.

These are plain `int`s written under `ipcMutex` during UAPI and read without synchronization on the send path. Taking `ipcMutex` (an `RWMutex`, `device.go:89`) per packet would add real contention to the transport data path (`:578`, per-packet in `RoutineSequentialSender`) and regress throughput.

**Fix:** make `imitate.proto` follow the *existing* pattern — a plain field, written under `ipcMutex` in UAPI, read lock-free on send. (Strictly, that read is a data race under the Go memory model, but it's the *same* pre-existing race as `paddings`/`junk`, and config is set before traffic; if you want it clean without contention, make `proto` an `atomic.Uint32` and `Load()` it — never the mutex.) Correct the spec's §8 wording accordingly. The `junkCounter atomic.Uint64` proposal is fine as-is.

---

## B. Tighten before merge (medium)

### B1 — "Byte-exact" needs a real cross-impl fixture, not mirrored asserts

The 41 `transform.rs` tests mostly assert *structure* (header bits, flags, RDLENGTH reaching end-of-datagram), not full-packet byte dumps. Mirroring them in Go proves *structural* conformance but does **not** enforce the "byte-exact port" claim — a PRNG byte-extraction or LCG-ordering bug (see the porter traps below) would pass structural tests while producing different bytes.

**Fix:** add a tiny Rust harness that dumps `hex(apply_padding(payload, pad_size, proto))` for a fixed grid of `(payload, pad_size, proto)`, check the vectors into the Go repo, and assert Go reproduces them exactly. This is the only thing that actually enforces byte-exactness, and it's cheap.

### B2 — The spec's site list predates `f4f4c99` (keepalive padding)

Commit `f4f4c99` moved the S4 transport-padding block **outside** the keepalive guard (`device/send.go:578-586`), so **keepalives are now S-padded too**. This is good (an unshaped keepalive would be a flow asymmetry), and the single `fillPadding` helper covers it automatically since it's the same transport site — but the spec's "4 S-padding sites" enumeration and its rationale should explicitly acknowledge keepalives are shaped, and note the transport site is structurally different from the other three (it shifts `elem.buffer` in place via a copy loop, then fills `elem.buffer[:padding]` — it does not allocate a fresh `buf`). The `fillPadding(buf, padding)` helper signature still works there; just be aware the call site isn't a clean mirror of the handshake sites.

### B3 — Drop the DNS `echo` parameter on the client

The spec carries `imitateDNS(buf, padding, echo *dnsEcho)`. The `echo` path in `transform.rs` exists so the **server responder** can echo a real incoming query's QNAME/TXID. A client has no incoming query to echo — it would always pass `None`. Port the no-echo path only; drop the param. Avoids dragging `responder.rs`'s query-parsing machinery into the client core for nothing.

---

## C. Minor / housekeeping (low)

- **`aSecCfg` doesn't exist** in this fork (§3 "beside the `aSecCfg` / junk fields"). The real config cluster is `junk`/`paddings`/`headers`/`ipackets` at `device/device.go:93-113`; put `imitate deviceImitate` right after `ipackets` (`:113`).
- **Line numbers throughout** have drifted (send sites are `161/209/246/578`, not `163/211/248/584`; junk `rand.Read(buf)` is at `:148` *inside* the `jc` loop at `:139-150`). The spec already says "re-grep before editing," so this is expected — just refresh the table when you start.
- **No standalone UAPI unit test exists yet** — parsing is exercised only via `device_test.go` integration tests (`genTestPair`/`uapiCfg`, e.g. `TestAWGDevicePing:228`). Add `device/uapi_test.go` for the `imitate_protocol` parse cases, and extend `TestAWGDevicePing` with `imitate_protocol=quic` as the cheapest anchor (patched↔patched passes traffic).

### Porter traps worth pinning in the spec (from the `transform.rs` read)

These are the bugs most likely to pass structural tests but fail byte-exactness (hence B1):
- **uint32 wrapping** — FNV multiply and the LCG must be `uint32` wraparound; Go does this natively *only* if the types are `uint32` (not `int`).
- **Byte extraction is `(state >> 16) & 0xff`** — the middle byte, not the low byte. Easy to get wrong.
- **Header fields are big-endian** (`to_be_bytes`): DNS TXID/flags, STUN type/cookie/txn, etc. Use `binary.BigEndian` explicitly.
- **QUIC byte0 uses `=`, not `|=`** — reserved bits 6-7 must stay 0.
- **`DNS_OPT_MIN == 32` is a hard branch** (full OPT vs NULL fallback); off-by-one flips the whole DNS strategy.
- **STUN advertises `written` (TLV bytes), not `body`** — advertising `body` overruns and yields a "Malformed Packet" fingerprint.
- **SIP `Content-Length` is a fixed-point solve** over {1–2 spaces}×{digit count}; the one/two-space fallback is load-bearing.
- **LCG state is consumed in a fixed order** (STUN: exactly 3 steps for the txn id before attributes; SIP: status/host/method/branch/tags/call-id/cseq in order). Reordering changes every byte.
- **DNS NULL fallback `rdlength = total_len.saturating_sub(28)`** — in Go, guard the unsigned subtraction (`if total_len > 28`), or it wraps.

---

## Strengths (keep these)

- The **cosmetic-rewrite proof** (sender-only + interop-with-vanilla as the anchor test) is the right backbone and is verified true here.
- The **additive obf-registry** approach for mechanism C is idiomatic to this codebase — no risk to `randObf`.
- The **threat model is honest** about layer-4/statistical being out of scope, and Tier 4's `Id`/`Ib` limits ("does nothing against a full QUIC state machine") are stated plainly. Don't let later edits over-claim.
- **Incremental tiers** are genuinely independently shippable; Tier 1 → vanilla-interop is a real milestone.

---

## Suggested spec edits checklist

- [ ] §3 / §5: replace single `imitateFill` with `imitateFillPrefix(buf, padding, proto)` (A) and `imitateFillWhole(buf, seed, proto)` (B/C); state that B/C bypass the `pad_size>=len` guard and take an injected seed. **(A1)**
- [ ] §8: correct the concurrency model — lock-free read of `proto` on the send path (or `atomic`), never the config lock. **(A2)**
- [ ] §9: add the Rust→Go golden-byte fixture as the enforcement of "byte-exact." **(B1)**
- [ ] §5: note keepalives are now S-padded (`f4f4c99`) and the transport site is an in-place shift. **(B2)**
- [ ] §3: drop the `echo` param from the client DNS writer. **(B3)**
- [ ] §3: fix `aSecCfg` → real field cluster; refresh drifted line numbers. **(C)**
- [ ] §7: pin the porter-traps list. **(C)**
