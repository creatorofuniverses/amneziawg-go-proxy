# Client-side traffic imitation for AmneziaWG (amneziawg-go) — Design

**Status:** approved design (code-review applied) / not yet built
**Date:** 2026-06-15
**Scope of this spec:** full design across all tiers; implementation proceeds incrementally, Tier 1 first.
**Implementation target:** the `amneziawg-go` Go core. Kernel module and Android are documented as follow-on porting work (§11).
**Review applied:** `docs/superpowers/reviews/2026-06-15-client-side-traffic-imitation-review.md` — A1 (two fill entry points, §3), A2 (lock-free `proto` read, §8), B1 (golden-byte fixture, §9), B2 (keepalive padding / in-place transport site, §5), B3 (drop DNS echo, §3/§7), plus drifted line numbers and porter-traps (§5/§7.6).

Source idea: `~/Documents/cloud-notes/.../Client-side traffic imitation for AmneziaWG.md`.
Fill reference (ported byte-exact): `amneziawg-install/amneziawg-proxy/src/transform.rs`.

---

## 1. Goal & motivation

The server-side `amneziawg-proxy` (`transform.rs`) rewrites the random `S1`–`S4`
padding prefix of outgoing AWG packets into **protocol-conformant filler** (fake
QUIC / DNS / STUN / SIP), so DPI sees plausible traffic instead of high-entropy
"unknown encrypted." It only shapes **server → client**.

This feature brings that imitation **natively into the `amneziawg-go` core** so it
also shapes **client → server**. Because WireGuard is peer-symmetric ("server" and
"client" are config conventions), a single patched core shapes **both directions**.
It also shapes the **junk packets** the sidecar proxy cannot (`classify_awg_packet`
returns `None` for them), closing the layer-3 asymmetry the note identifies as the
sidecar's core flaw.

### Threat model — stated honestly

| DPI technique | Defeated by |
|---|---|
| Byte-signature (WG fixed fields) | AWG native (`S` padding + `H` randomization) — already shipped |
| Protocol-positive ("is this an allowed protocol?") | **This feature** (Tiers 1–3) |
| Flow-consistency (stateful, both directions) | **This feature, client-side shaping** (Tier 2 closes junk asymmetry) |
| Cheap SNI filtering / JA3-JA4 fingerprinting | **Tier 4** (`Id` / `Ib`) |
| Statistical / behavioral (sizes, timing, duration) | **Nothing here** — out of scope, header shaping is irrelevant |
| Active probing | Server `responder.rs` (client doesn't listen → N/A) |

This feature does **nothing** for layer-4 statistical analysis. That limit is
explicit so the protection is not over-trusted.

## 2. The decisive property: the rewrite is cosmetic

Receivers strip padding by **size-matching** and validate the magic header at
offset `padding` — they **never inspect padding content**:

- `device/receive.go` `DeterminePacketTypeAndPadding`: `if size == padding+MessageInitiationSize { validate at packet[padding:] }`
- `device/obf_rand.go:28`: *"there is no way to validate randomness :) assume that it is always true."*

Three consequences that anchor the whole design:

1. **Sender-only.** Only the send path is patched; receive is untouched.
2. **Interops with a vanilla peer.** An unmodified peer accepts protocol-shaped
   padding exactly as it accepts random padding. This is the anchor test.
3. **Length-invariant.** Fill must be exactly `padding` bytes — an in-place,
   same-length rewrite, identical to the `rand.Read` it replaces. MTU math, the
   magic-header offset, and interop are all unaffected.

The one constraint: the magic header (uint32 in the `H` range) sits at offset
`padding`, so a dissector must consume exactly the padding region and treat
`[magic header + ciphertext]` as opaque protocol payload. That needs `S` large
enough to hold a plausible header; `transform.rs` has small-pad fallbacks, ported
here (§7).

## 3. Architecture (Approach A: free-function dispatch + thin obf adapter)

New self-contained file **`device/obf_imitate.go`**, a byte-exact port of
`transform.rs`:

```go
type imitateProto uint8
const ( imitateNone imitateProto = iota; imitateQUIC; imitateDNS; imitateSTUN; imitateSIP )

// TWO entry points (see §3 "Two fill entry points" — resolves review finding A1):
//
// Mechanism A — prefix fill on a real packet. Byte-exact port of apply_padding,
// INCLUDING its no-op guard (pad_size == 0 || pad_size >= len). Seed is derived
// internally from the real ciphertext after the prefix: fnv1aSeed(buf[padding:]).
func imitateFillPrefix(buf []byte, padding int, p imitateProto)

// Mechanisms B & C — the whole datagram is fake. NO guard (we WANT padding == len).
// Seed is INJECTED by the caller (junk: device counter; I-packet: its own counter),
// because buf[padding:] would be empty here and fnv1aSeed([]) is a constant → every
// junk/I-packet would be byte-identical, itself a signature.
func imitateFillWhole(buf []byte, seed uint32, p imitateProto)

func fnv1aSeed(payload []byte) uint32                        // FNV-1a over first 64 bytes of payload
func lcgStep(state uint32) uint32                            // glibc LCG: state*1103515245 + 12345

// protocol writers, byte-for-byte from transform.rs. Each takes the buffer split
// point + an externally-supplied seed, so the same writer serves both entry points:
//   - prefix:  imitateFillPrefix passes seed = fnv1aSeed(buf[padding:])
//   - whole:   imitateFillWhole passes the injected counter seed, split at len(buf)
// The DNS writer drops transform.rs's server-only `echo` param (review B3): a client
// has no incoming query to echo, so only the no-echo path is ported.
func imitateQUICShort(buf []byte, padding int, seed uint32)
func imitateDNS(buf []byte, padding int, seed uint32)        // + imitateDNSNull small-pad fallback
func imitateSTUN(buf []byte, padding int, seed uint32)
func imitateSIP(buf []byte, padding int, seed uint32)
```

Both entry points dispatch on `proto` with a `switch` (closed set of 4 protocols —
matches the Rust `match`; no strategy interface, per YAGNI). `imitateFillPrefix` is
the byte-exact port (keeps the guard, self-seeds); `imitateFillWhole` skips the
guard and takes the seed as a parameter. Tier 1's `fillPadding` helper wraps
`imitateFillPrefix`; Tiers 2/3 wrap `imitateFillWhole`.

> **Realism cost of whole-datagram fill (honest note, per the threat-model tone):**
> a whole-datagram DNS/STUN/SIP fill has *empty* option-data/body (no trailing
> ciphertext to carry), and a junk flow of 1-RTT *short-header* QUIC packets with no
> preceding Initial does not resemble a connection opening. Fine for layer-3
> protocol-positive checks; adds nothing against a stateful parser — which is exactly
> what Tier 4 `Id`/`qinit` addresses.

### Data flow

```
send path:  [ S-pad prefix | magic hdr | WG ciphertext ]
                  ↑ rewritten in place, exactly `padding` bytes, never reads past it for length
            imitateFillPrefix(buf, padding, dev.imitate.proto)   // self-seeds from buf[padding:]
```

Receive path: **unchanged**.

### Seeding model (differs per mechanism — drives the two entry points above)

- **S-padding (A):** `buf[padding:]` is real ciphertext → `imitateFillPrefix` self-seeds from it (exactly like the proxy).
- **Junk (B):** whole datagram is fake, no trailing payload → `imitateFillWhole` with an injected **device counter** seed, fill the entire buffer (`padding == len(buf)`).
- **I-packets (C):** `imitateObf` adapter calls `imitateFillWhole` with its own counter seed.

### Device state

A small `imitate` struct on `Device`, placed right after the `ipackets` field in
the existing config cluster (`device/device.go` `junk`/`paddings`/`headers`/`ipackets`,
~`:93-113`). Set from UAPI under `ipcMutex` (write side only — see §8 for the
lock-free read on the send path):

```go
type deviceImitate struct {
    proto       atomic.Uint32   // imitateProto; Store() under ipcMutex in UAPI, Load() lock-free on send (§8)
    junkCounter atomic.Uint64   // seeds junk-packet fill (mechanism B)
    sni         string          // Tier 4 (Id)
    fingerprint string          // Tier 4 (Ib)
}
```

(`proto` is `atomic.Uint32` rather than a plain field so the lock-free send-path
read is race-clean without per-packet locking — see §8 / review A2. A plain field
read lock-free would also work, matching the pre-existing `paddings`/`junk` pattern,
but `atomic` is the clean version at no contention cost.)

## 4. Configuration (UAPI)

AWG config arrives as a UAPI string (`IpcSet`), parsed in `device/uapi.go` beside
the `jc` / `s1`–`s4` / `i1`–`i5` handlers.

```
imitate_protocol = none | quic | dns | stun | sip        # default: none
```

- Parsed in the same `switch` as `jc`/`s1` (slots after the `s4` case, `device/uapi.go` ~`:385`); mapped to `imitateProto` and `Store()`d into `imitate.proto` while `ipcMutex` is held for the whole `IpcSetOperation`. **Read** lock-free on the send path (§8).
- **Backward compatible:** absent or `none` → every mechanism keeps calling `rand.Read`, identical to today. No change required in the Android/desktop config layers to keep working; they add the key only to opt in.
- One setting propagates to all three mechanisms so the whole flow is consistent.

**Tier-4 keys** (documented now, built later):
```
imitate_sni         = <domain>            # Id — fake QUIC Initial + ClientHello SNI, via I-packet path
imitate_fingerprint = chrome | firefox    # Ib — uTLS-style ClientHello fingerprint
```

### The `imitateObf` adapter (mechanism C)

Implements the existing `obf` interface (parallel to `randObf` in `obf_rand.go`),
so it drops into `obfChain` unchanged. **One builder per protocol**, registered in
`obfBuilders` (`obf.go`): `q`, `dns`, `stun`, `sip`. Configured as `i1=<q 600>`.

```go
type imitateObf struct { length int; proto imitateProto; counter uint32 }
func newImitateObf(proto imitateProto) obfBuilder    // closure → register q/dns/stun/sip
func (o *imitateObf) Obfuscate(dst, src []byte)      // imitateFillWhole(dst, o.nextSeed(), o.proto) — whole datagram, injected seed
func (o *imitateObf) Deobfuscate(dst, src []byte) bool { return true }   // cosmetic, like randObf
func (o *imitateObf) ObfuscatedLen(n int) int  { return o.length }
func (o *imitateObf) DeobfuscatedLen(n int) int { return 0 }
```

The adapter uses `imitateFillWhole` with an **injected, varying** seed (not the
self-seeding prefix path), so a chain of I-packets is not byte-identical (review A1).

`randObf` is **not** modified — imitation is purely additive via the registry.

## 5. The three mechanisms & exact call-site edits

Verified line numbers in this fork (subject to drift — re-grep `rand.Read` in
`device/` before editing).

**Mechanism A — S-padding (4 sites).** `imitateFillPrefix`, self-seeds from `buf[padding:]`.
Line numbers are ground-truth as of this review (re-grep `rand.Read` before editing — they drift).

| Site | Context | Shape |
|---|---|---|
| `device/send.go:161` | handshake init | fresh `buf`, `rand.Read(buf[:padding])` |
| `device/send.go:209` | handshake response | fresh `buf` |
| `device/send.go:246` | cookie reply | fresh `buf` |
| `device/send.go:578` | transport data **+ keepalive** | **in-place shift** (see below) |

**Keepalives are S-padded too (since `f4f4c99`).** The transport block at `:578`
runs *regardless* of the `len(elem.packet) != MessageKeepaliveSize` check, so the
helper shapes keepalives as well — desirable (an unshaped keepalive would be a flow
asymmetry). This site is **structurally different** from the other three: it shifts
`elem.packet` forward inside the already-allocated `elem.buffer` via a copy loop,
then fills `elem.buffer[:padding]` — it does not allocate a fresh `buf`. The
`fillPadding(buf, padding)` helper still applies (pass `elem.buffer`), but the call
site isn't a clean mirror of the handshake sites.

**Mechanism B — junk packets (1 site).** `device/send.go:148` (`rand.Read(buf)`, inside the `jc` loop at `:139-150`).
Whole datagram is fake → seed from the device counter, fill the entire buffer with
`padding == len(buf)`. The protocol writers that frame "payload after padding"
(DNS OPT option-data, STUN trailing, SIP body) treat the whole datagram as the
message. This is the one place the port diverges structurally from `transform.rs`
(which cannot shape junk) → dedicated tests.

**Mechanism C — I-packets (1 site).** `device/obf_rand.go:24` is `randObf`; the new
`imitateObf` sits beside it, additive via the registry.

### Single gate helper

The proto check lives in one place so the four S-padding sites stay one-liners:

```go
func (device *Device) fillPadding(buf []byte, padding int) {
    if p := imitateProto(device.imitate.proto.Load()); p != imitateNone {
        imitateFillPrefix(buf, padding, p)   // self-seeds from buf[padding:]
    } else {
        rand.Read(buf[:padding])
    }
}
```

The `proto.Load()` is lock-free (§8). **Length invariance** is preserved at every
site: `imitateFillPrefix` writes exactly `padding` bytes (and `imitateFillWhole`
exactly `len(buf)` for junk/I-packets), identical to the `rand.Read` it replaces.

## 6. Incremental build tiers

Each tier is independently shippable and testable against a vanilla peer.

- **Tier 1 — MVP.** `obf_imitate.go` (PRNG + all four protocol writers, byte-exact),
  `imitateProto` type, `dev.fillPadding` helper, the 4 S-padding swaps, and the
  `imitate_protocol` UAPI key (default `none`). Anchor test: patched sender ↔
  vanilla peer passes traffic.
- **Tier 2 — junk.** Wire `send.go:148` to device-counter-seeded full-datagram
  fill. Closes the layer-3 asymmetry.
- **Tier 3 — I-packets + selector.** Register `q`/`dns`/`stun`/`sip` builders;
  finalize the device-level selector across all mechanisms.
- **Tier 4 — richer imitation (§7.5).**

## 7. Protocol fill details (ported byte-exact from transform.rs)

The PRNG is shared by all protocols: `fnv1aSeed` (FNV-1a offset basis `0x811c9dc5`,
prime `0x01000193`, over the first 64 payload bytes) seeds a glibc `lcgStep`
(`*1103515245 + 12345`). Deterministic, payload-derived, no `crypto/rand`.

- **QUIC** (`imitateQUICShort`): 1-RTT short header for every AWG phase. Byte 0 =
  `0x40 | (spin<<5) | (key_phase<<2) | pn_len_bits`; bytes 1+ pseudo-random. No
  version/length field, so the tail is indistinguishable from 1-RTT ciphertext.
  Long-header / Initial forms are deliberately avoided (RFC 9000 §14.1 forces
  Initials to ≥1200 B, which the fixed `S1+148` size cannot meet).
- **DNS** (`imitateDNS`): EDNS **OPT response** (RFC 6891) whose unknown option
  (`0xFDE9`, local-use range) carries the ciphertext as opaque option-data, so the
  whole datagram parses as one well-formed DNS message with no trailing bytes.
  Header flags `0x8180` (QR/RD/RA, NOERROR), `QDCOUNT=1`, `ARCOUNT=1`. Falls back
  to legacy `TYPE NULL` (`imitateDNSNull`) for `pad_size < 32` (`DNS_OPT_MIN`).
- **STUN** (`imitateSTUN`): Binding Success Response (`0x0101`, RFC 5389 magic
  cookie `0x2112A442`, payload-derived 96-bit txn ID), with XOR-MAPPED-ADDRESS +
  SOFTWARE attributes when room allows. Advertised length covers exactly the TLVs
  written (no overrun → no "Malformed Packet" fingerprint); SOFTWARE value clamped
  to 124 (RFC 5389 §15.10).
- **SIP** (`imitateSIP`): SIP response header block (`SIP/2.0` status line + Via /
  From / To / Call-ID / CSeq, canonical order), greedily packed, with a
  `Content-Length` covering the whole body when all mandatory headers fit; CRLF /
  space-fill remainder. Small-pad fallback to a status-line fragment + CRLF.

Edge cases (all from `transform.rs`, preserved): `pad_size == 0` or
`pad_size >= len` → no-op **in the prefix path only** (`imitateFillPrefix`);
`imitateFillWhole` deliberately omits this guard (review A1); partial-header writes
for tiny pads; seed-derived txn/transaction IDs stable across pad sizes. The DNS
writer ports only the **no-echo** path — the server-side query-echo (`echo` param +
`responder.rs` query parsing) is not relevant on a client (review B3).

### 7.6 Porter traps (most likely to pass structural tests but break byte-exactness)

These are the byte-level pitfalls behind the golden-fixture requirement (§9 B1):

- **uint32 wraparound** — FNV multiply and the LCG must use `uint32` types (Go wraps natively only for unsigned, not `int`).
- **Byte extraction is `(state >> 16) & 0xff`** — the *middle* byte, not the low byte.
- **Headers are big-endian** (`to_be_bytes`): DNS TXID/flags, STUN type/cookie/txn — use `binary.BigEndian` explicitly.
- **QUIC byte 0 uses `=`, not `|=`** — reserved bits 6–7 must stay 0.
- **`DNS_OPT_MIN == 32` is a hard branch** (full OPT vs NULL fallback); off-by-one flips the DNS strategy.
- **STUN advertises `written` (TLV bytes), not `body`** — advertising `body` overruns → "Malformed Packet".
- **SIP `Content-Length` is a fixed-point solve** over {1–2 spaces}×{digit count}; the one/two-space fallback is load-bearing.
- **LCG state is consumed in a fixed order** (STUN: exactly 3 steps for the txn id before attributes; SIP: status/host/method/branch/tags/call-id/cseq in order). Reordering changes every byte.
- **DNS NULL fallback `rdlength = total_len - 28`** — guard the unsigned subtraction (`if total_len > 28`) or it wraps (Rust uses `saturating_sub`).

### 7.5 Tier 4 — fake QUIC Initial with SNI (`Id`)

A **different shape** from Tiers 1–3: not a same-length prefix rewrite but a
**crafted standalone I-packet** sent before the handshake (`send.go:131-137`), so
length is free (I-packets are their own datagrams). Tier 4 ships **`Id` only**;
`Ib` (uTLS JA3/JA4 fingerprinting) is deferred to a later tier (see end of section).

**Scope decisions (brainstorm 2026-06-16):**
- **`Id` only, no uTLS.** The full RFC 9001 Initial is built with Go **std crypto**
  (`crypto/aes` + AES-GCM + `crypto/hkdf`, all in Go 1.24) — the fork takes **no new
  dependency**.
- **Generic valid TLS 1.3 ClientHello.** A single fixed, well-formed ClientHello
  (TLS1.3 `supported_versions`, ciphers `0x1301/02/03`, x25519 `key_share`,
  `signature_algorithms`, ALPN `h3`, `quic_transport_parameters`, + the SNI). It
  parses cleanly and carries a *static* JA3 — **not** a real browser's. Matching a
  browser JA3/JA4 is exactly the deferred `Ib` work, not a half-measure here.
- **`crypto/rand` for the random fields** (DCID, SCID, packet number, ClientHello
  random, x25519 key_share). Matches real QUIC client behavior, makes consecutive
  Initials differ for free (no byte-identical signature), and there is no Rust
  reference to golden-vector against anyway.
- **`i1=<qinit example.com>`, fixed 1200 B.** `ObfuscatedLen(0) = 1200`; PADDING
  frames tune the datagram to exactly 1200 (RFC 9000 §14.1 client-Initial minimum),
  accounting for the 16-byte GCM tag. **No separate device-level `imitate_sni`
  key** — the self-contained builder supersedes spec §4's `imitate_sni`/`imitate_fingerprint`
  keys (YAGNI; consistent with the Tier-3 mechanism-C registry pattern).

**`Id` build (mechanism C, new `obf` builder `qinit` in a new file `device/obf_imitate_quic.go`):**
1. Register `qinit` in `obfBuilders` beside Tier-3 `q`/`dns`/`stun`/`sip`. No
   `send.go` change — the I-packet path already calls `ObfuscatedLen`+`Obfuscate`.
2. `Obfuscate(dst,nil)` builds: QUIC long-header **Initial** → CRYPTO frame → TLS
   **ClientHello** with the configured SNI → PADDING to exactly 1200 B → Initial
   header + packet protection using the **RFC 9001 v1 well-known salt**
   (`0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`, no secrets — fully reproducible;
   any DPI can derive the keys and read the benign SNI, which is the point).
3. Defeats cheap line-rate SNI filtering. Does **nothing** against a DPI running a
   full QUIC state machine (the fake handshake never completes — no real
   ServerHello/key exchange) and a lone Initial with no follow-up is itself a weak
   flow signal. Documented honestly.

**Testing — round-trip replaces golden vectors.** `transform.rs` has no long-header
Initial, so there is no byte-exact reference. The correctness guard is a
**self-decrypt round-trip**: read the DCID back out of the produced packet, derive
the same Initial keys, strip header protection, AES-128-GCM-open, parse the CRYPTO
frame + ClientHello, assert SNI == the configured domain. A wrong header-protection
mask or AEAD nonce still yields 1200 plausible bytes, so this round-trip is what
actually catches silent crypto/framing bugs (the Tier-4 analogue of §7.6).

**Tier-4 porter-traps (crypto specifics that pass structural tests but break decrypt):**
- HKDF chain: `initial_secret = HKDF-Extract(v1_salt, DCID)`; `client_initial =
  Expand-Label(initial_secret, "client in", "", 32)`; then `quic key`(16)/`quic iv`(12)/`quic hp`(16).
- `hkdfExpandLabel` uses the **TLS 1.3 `"tls13 "` label prefix** inside the HkdfLabel struct.
- AEAD nonce = `iv XOR left-padded packet number` (12 bytes).
- Header protection: AES-128-**ECB** single block over the 16-byte **sample at
  `pn_offset + 4`**; mask byte0 low **4** bits (long header) + the PN bytes.
- QUIC **varint** length field (2-byte form at 1200 B); first byte `0xC3`
  pre-protection (form+fixed+Initial type + 4-byte PN length).
- Datagram-size accounting: solve PADDING so `header + PN + ciphertext + 16-byte tag
  == 1200` exactly.

**Deferred — `Ib` (fingerprint), a later tier:**
- Order ClientHello cipher suites / extensions / ALPN / QUIC transport params to
  match a target browser (JA3/JA4). Reference: `refraction-networking/utls`
  presets rather than hand-rolling (which goes stale each browser release).
- Heaviest, most fragile part — build **last**, ship only against a known JA3/JA4
  adversary. Embedding uTLS in the core is a dependency-weight decision (§10 risk).

## 8. Error handling & edge cases

- **Length invariance is a hard invariant** — every writer fills exactly `padding`
  (or `len(buf)` for junk). A unit test asserts `len` unchanged and `buf[padding:]`
  untouched for every protocol × pad-size.
- **Tiny pads** (`padding < protocol minimum`) → small-pad fallbacks (QUIC partial,
  DNS NULL, STUN/SIP fragments), ported verbatim. Never panic, never length-drift.
- **`proto == imitateNone`** → `rand.Read` path; zero behavior change.
- **MTU:** unchanged — same byte count as before; existing junk/signature MTU
  guidance in CLAUDE.md still applies.
- **Concurrency (corrected per review A2):** `proto` is **read lock-free** on the
  send path — `imitate.proto.Load()` (`atomic.Uint32`), written via `Store()` under
  `ipcMutex` in UAPI. This matches the existing `paddings`/`junk` pattern, which are
  also read lock-free on the hot path (`send.go:139-141, 161, 209, 246, 578`).
  **Do not take `ipcMutex` per packet** — it is an `RWMutex` and would add real
  contention to the transport data path (`RoutineSequentialSender`, per-packet).
  The junk counter is `atomic.Uint64`. Protocol writers are pure functions of
  `(buf, padding, seed)` — no shared mutable state.

## 9. Testing strategy

1. **Byte-exact golden fixture (the real enforcement of "byte-exact" — review B1).**
   The 41 `transform.rs` `#[test]`s mostly assert *structure* (header bits, RDLENGTH
   reaching end-of-datagram), not full-packet byte dumps — so mirroring them proves
   structural conformance but NOT byte-exactness (a PRNG-extraction or LCG-ordering
   bug from §7.6 would pass). So: add a tiny Rust harness that dumps
   `hex(apply_padding(payload, pad_size, proto))` for a fixed grid of
   `(payload, pad_size, proto)`, check the vectors into the Go repo
   (e.g. `device/testdata/imitate_vectors.json`), and assert the Go port reproduces
   them exactly. This is cheap and is the only thing that actually enforces the claim.
2. **Structural unit tests:** port the `transform.rs` `#[test]` asserts as a second
   layer (QUIC header bits, DNS OPT framing, STUN TLVs, SIP header block) + assert
   `buf[padding:]` untouched for every protocol × pad-size.
3. **Junk / I-packet (whole-datagram):** seeded-varying fill (mechanism B/C) — assert
   consecutive packets are NOT byte-identical (the A1 failure mode), well-formed with
   `padding == len(buf)`.
4. **Interop (anchor test):** two `ip netns`, **patched sender ↔ vanilla peer**
   (`tests/netns.sh`), bring up tunnel, ping/iperf. Vanilla acceptance *proves* the
   cosmetic claim. Then patched ↔ patched. Bonus: patched-go ↔ vanilla-kernel.
   No standalone UAPI parse test exists yet — add `device/uapi_test.go` for the
   `imitate_protocol` cases, and extend `TestAWGDevicePing` (`device_test.go`) with
   `imitate_protocol=quic` as the cheapest patched↔patched anchor.
5. **Realism:** `tcpdump` the veth → Wireshark / QUIC parser → confirm classification
   as the chosen protocol and that it consumes exactly `padding` bytes.
6. **Formatting:** `go test ./...` includes `TestFormatting` — keep all new files gofmt-clean.
7. **Fuzz:** tiny `s` values, `padding < header size` → confirm fallback, no panic, no length drift.

## 10. Risks & costs

- **Fork maintenance** — carry a patched core; rebase on upstream AWG releases.
  Keep changes isolated (new file + minimal `send.go`/`uapi.go`/`obf.go` edits) to
  ease merges, per CLAUDE.md.
- **Userspace-only (Go)** vs kernel throughput — Go core first; kernel port (§below)
  only if throughput demands.
- **No layer-4 coverage** — sizes/timing unchanged. Stated, not hidden.
- **Junk-vs-mimic tension** — shaping `Jc` junk (Tier 2) reconciles the flow look
  but blunts junk's original size/timing-noise purpose. Decision (approved): shape
  junk as the chosen protocol.
- **Tier-4 `Ib` weight/fragility** — uTLS dependency in the core; browser
  fingerprints go stale. Build last, gate on a real JA3/JA4 adversary.
- **Probe responder not included** — keep the server's `responder.rs` if active
  probing is in scope (layer 5, orthogonal to this feature).

## 11. Follow-on porting (out of scope for this spec, documented)

- **Android** (`amneziawg-android`) — embeds this same `amneziawg-go` as a Go-module
  dependency (`libwg-go/go.mod`). §3–§7 apply **verbatim**; differences are
  build/dist only (a `replace` directive to the fork; no Java/Kotlin change for
  Tier 1's QUIC default; optional Kotlin UI toggle later). One fork serves both
  desktop-userspace and Android clients.
- **Kernel module** (`amneziawg-linux-kernel-module`) — same wire format and cosmetic
  property; ~4 send sites + 1 modifier (`socket.c`, `send.c`, `junk.c`). Port the
  PRNG + header builders to plain C (`GFP_ATOMIC` hot path discipline at
  `send.c:260`). A patched Go client interoperates with a vanilla kernel server, so
  prototype in Go and port to the kernel only for throughput.

## 12. Reference paths

- Fill reference: `amneziawg-install/amneziawg-proxy/src/transform.rs` (+ `responder.rs`)
- Go core: `device/{send.go,receive.go,obf*.go,uapi.go,device.go}`
- Kernel core: `amneziawg-linux-kernel-module/src/{send.c,socket.c,receive.c,junk.c,magic_header.c}`
- Android: `amneziawg-android/tunnel/tools/libwg-go/{go.mod,api-android.go,Makefile}`
- Source idea note: `~/Documents/cloud-notes/CloudNotes2.0/Projects/Me/VPN/awg3/Client-side traffic imitation for AmneziaWG.md`
- Code review of this spec: `docs/superpowers/reviews/2026-06-15-client-side-traffic-imitation-review.md`
