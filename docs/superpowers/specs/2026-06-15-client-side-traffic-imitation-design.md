# Client-side traffic imitation for AmneziaWG (amneziawg-go) — Design

**Status:** approved design / not yet built
**Date:** 2026-06-15
**Scope of this spec:** full design across all tiers; implementation proceeds incrementally, Tier 1 first.
**Implementation target:** the `amneziawg-go` Go core. Kernel module and Android are documented as follow-on porting work (§9).

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

func imitateFill(buf []byte, padding int, p imitateProto)   // mirrors apply_padding(data, pad_size, proto)
func fnv1aSeed(payload []byte) uint32                        // FNV-1a over first 64 bytes of payload
func lcgStep(state uint32) uint32                            // glibc LCG: state*1103515245 + 12345

// protocol writers, byte-for-byte from transform.rs. Each takes the full buffer
// + padding length and splits at `padding` internally (matching the Rust
// (data, pad_size) signatures), so the writer alone decides how the seed payload
// (buf[padding:]) maps into the message framing:
func imitateQUICShort(buf []byte, padding int)
func imitateDNS(buf []byte, padding int, echo *dnsEcho)      // + imitateDNSNull small-pad fallback
func imitateSTUN(buf []byte, padding int)
func imitateSIP(buf []byte, padding int)
```

`imitateFill` dispatches on `proto` with a `switch` (closed set of 4 protocols —
matches the Rust `match`; no strategy interface, per YAGNI).

### Data flow

```
send path:  [ S-pad prefix | magic hdr | WG ciphertext ]
                  ↑ rewritten in place, exactly `padding` bytes, never reads past it for length
            imitateFill(buf, padding, dev.imitate.proto)
            seed = fnv1aSeed(buf[padding:])   // real ciphertext → deterministic, per-packet variety
```

Receive path: **unchanged**.

### Seeding model (differs per mechanism)

- **S-padding (A):** `buf[padding:]` is real ciphertext → seed from it (exactly like the proxy).
- **Junk (B):** whole datagram is fake, no trailing payload → seed from a **device counter**, fill the entire buffer.
- **I-packets (C):** `imitateObf` adapter delegates to the same writers.

### Device state

A small `imitate` struct on `Device`, set from UAPI under the existing config lock
(beside the `aSecCfg` / junk fields):

```go
type deviceImitate struct {
    proto       imitateProto
    junkCounter atomic.Uint64   // seeds junk-packet fill (mechanism B)
    sni         string          // Tier 4 (Id)
    fingerprint string          // Tier 4 (Ib)
}
```

## 4. Configuration (UAPI)

AWG config arrives as a UAPI string (`IpcSet`), parsed in `device/uapi.go` beside
the `jc` / `s1`–`s4` / `i1`–`i5` handlers.

```
imitate_protocol = none | quic | dns | stun | sip        # default: none
```

- Parsed in the same `switch` as `jc`/`s1`; mapped to `imitateProto`, stored under the config lock.
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
type imitateObf struct { length int; proto imitateProto }
func newImitateObf(proto imitateProto) obfBuilder    // closure → register q/dns/stun/sip
func (o *imitateObf) Obfuscate(dst, src []byte)      // imitateFill(dst, len(dst), o.proto) — whole datagram
func (o *imitateObf) Deobfuscate(dst, src []byte) bool { return true }   // cosmetic, like randObf
func (o *imitateObf) ObfuscatedLen(n int) int  { return o.length }
func (o *imitateObf) DeobfuscatedLen(n int) int { return 0 }
```

`randObf` is **not** modified — imitation is purely additive via the registry.

## 5. The three mechanisms & exact call-site edits

Verified line numbers in this fork (subject to drift — re-grep `rand.Read` in
`device/` before editing).

**Mechanism A — S-padding (4 sites).** Seed from `buf[padding:]` (real ciphertext).

| Site | Context |
|---|---|
| `device/send.go:163` | handshake init |
| `device/send.go:211` | handshake response |
| `device/send.go:248` | cookie reply |
| `device/send.go:584` | transport data |

**Mechanism B — junk packets (1 site).** `device/send.go:148` (`rand.Read(buf)`).
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
    if p := device.imitate.proto; p != imitateNone {
        imitateFill(buf, padding, p)
    } else {
        rand.Read(buf[:padding])
    }
}
```

**Length invariance** is preserved at every site: `imitateFill` writes exactly
`padding` bytes (or exactly `len(buf)` for junk), identical to the `rand.Read` it
replaces.

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
`pad_size >= len` → no-op; partial-header writes for tiny pads; payload-derived
txn/transaction IDs stable across pad sizes.

### 7.5 Tier 4 — fake QUIC Initial with SNI (`Id`) and fingerprint (`Ib`)

A **different shape** from Tiers 1–3: not a same-length prefix rewrite but a
**crafted standalone I-packet** sent before the handshake (`send.go:131-137`), so
length is free (I-packets are their own datagrams).

**`Id` (SNI) — the fake Initial:**
1. Hook the I-packet path with a `qinit` generator: `i1=<qinit example.com>`.
2. Build QUIC long-header **Initial** → CRYPTO frame → TLS **ClientHello** with
   `SNI = imitate_sni` → pad to ≥1200 B (RFC 9000 §14.1) → apply Initial header +
   packet protection using the **RFC 9001 well-known salt** (no secrets — fully
   reproducible; any DPI can derive the keys and read the benign SNI, which is the
   point).
3. Defeats cheap line-rate SNI filtering. Does **nothing** against a DPI running a
   full QUIC state machine (the fake handshake never completes — no real
   ServerHello/key exchange). Documented honestly.

**`Ib` (fingerprint) — uTLS profiles:**
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
- **Concurrency:** `proto` is read under the config lock (set rarely via UAPI);
  the junk counter is `atomic`. Protocol writers are pure functions of
  `(buf, padding, seed)` — no shared mutable state.

## 9. Testing strategy

1. **Unit (correctness):** golden tests on each writer — port the `transform.rs`
   `#[test]` vectors directly (QUIC header bits, DNS OPT framing, STUN TLVs, SIP
   header block). Assert exact length + protocol structure + `buf[padding:]`
   untouched. Byte-exact port means Go output must equal the Rust golden bytes.
2. **Junk-specific:** standalone-datagram tests (mechanism B) — whole-buffer fill,
   counter-seeded, well-formed protocol message with `padding == len(buf)`.
3. **Interop (anchor test):** two `ip netns`, **patched sender ↔ vanilla peer**
   (`tests/netns.sh`), bring up tunnel, ping/iperf. Vanilla acceptance *proves* the
   cosmetic claim. Then patched ↔ patched. Bonus: patched-go ↔ vanilla-kernel.
4. **Realism:** `tcpdump` the veth → Wireshark / QUIC parser → confirm classification
   as the chosen protocol and that it consumes exactly `padding` bytes.
5. **Formatting:** `go test ./...` includes `TestFormatting` — keep all new files gofmt-clean.
6. **Fuzz:** tiny `s` values, `padding < header size` → confirm fallback, no panic, no length drift.

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
