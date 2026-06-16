# Client Imitation Tier 4 (`Id` — fake QUIC Initial + SNI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `i1=<qinit example.com>` I-packet builder that emits a real, fully-protected 1200-byte QUIC v1 long-header **Initial** carrying a TLS 1.3 ClientHello with the configured SNI, so a line-rate DPI filter sees a plausible QUIC connection opening to a benign domain instead of an opaque AWG handshake.

**Architecture:** This is mechanism C (I-packets), like Tier 3 — a new `obf` builder registered in `obfBuilders` (`device/obf.go`), invoked at the existing I-packet send site (`device/send.go:131-137`), so **no `send.go` change**. Unlike Tiers 1–3 (same-length, deterministic, payload-derived rewrites locked by Rust golden vectors), Tier 4 is a **crafted standalone datagram** built fresh per call with `crypto/rand`, sized to exactly 1200 B (RFC 9000 §14.1). There is no upstream reference (`transform.rs` has no long-header Initial), so correctness is enforced two ways: (a) the crypto core is validated **byte-exact against RFC 9001 Appendix A.1 test vectors**, and (b) the assembled packet is validated by a **self-decrypt round-trip** that recovers and asserts the SNI. All crypto is Go std (`crypto/aes`, `crypto/cipher` AES-GCM, `crypto/hkdf`, `crypto/sha256`) — **no new dependency, no uTLS**. `Ib` (JA3/JA4 fingerprinting) is explicitly deferred to a later tier.

**Tech Stack:** Go 1.24.4, no CGO. New file `device/obf_imitate_quic.go` (+ `_test.go`) under `device/`. Tests via `go test ./device`.

**Spec:** `docs/superpowers/specs/2026-06-15-client-side-traffic-imitation-design.md` §7.5 (refined 2026-06-16: Id-only, generic TLS 1.3 ClientHello, `crypto/rand`, `<qinit domain>` fixed 1200, round-trip testing, no separate `imitate_sni` key).

**Out of scope (a later tier):** `Ib` / uTLS browser-fingerprint matching, the `imitate_fingerprint` key, and any device-level `imitate_sni` key (superseded by the self-contained `qinit` builder).

---

## File Structure

- **Create** `device/obf_imitate_quic.go` — RFC 9001 crypto helpers (salt, HKDF-Expand-Label, Initial key derivation, AES-GCM, header-protection mask, QUIC varint), the TLS ClientHello + CRYPTO-frame builders, the full Initial assembler `buildQUICInitial`, and the `qinitObf` registry adapter. Self-contained, parallel to `obf_imitate.go`. Carries the `// SPDX-License-Identifier: MIT` header.
- **Create** `device/obf_imitate_quic_test.go` — RFC 9001 A.1 key-derivation golden test, ClientHello structural test, full-packet round-trip decrypt + variation tests, registry/UAPI tests.
- **Modify** `device/obf.go:11-26` — register `qinit` in `obfBuilders`.
- **Modify** `device/device_test.go` — append the patched-sender ↔ vanilla-peer interop test.
- **Modify** `CLAUDE.md` — document the `qinit` I-packet tag under the imitation runtime note.

---

## Task 1: RFC 9001 crypto core (key derivation, AEAD, header protection, varint)

This is the riskiest part and is locked **byte-exact** by the RFC 9001 Appendix A.1 vectors, so it goes first and standalone.

**Files:**
- Create: `device/obf_imitate_quic.go`
- Test: `device/obf_imitate_quic_test.go`

- [ ] **Step 1: Write the failing test (RFC 9001 A.1 golden vectors)**

Create `device/obf_imitate_quic_test.go`. RFC 9001 Appendix A.1 fixes the client Initial keys for `DCID = 0x8394c8f03e515708`; reproducing them validates the salt, HKDF-Extract, and every Expand-Label.

```go
// SPDX-License-Identifier: MIT

package device

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// RFC 9001 Appendix A.1: client Initial keys for DCID 0x8394c8f03e515708.
func TestDeriveInitialKeysRFC9001(t *testing.T) {
	dcid := mustHex(t, "8394c8f03e515708")
	key, iv, hp := deriveInitialKeys(dcid)

	wantKey := mustHex(t, "1f369613dd76d5467730efcbe3b1a22d")
	wantIV := mustHex(t, "fa044b2f42a3fd3b46fb255c")
	wantHP := mustHex(t, "9f50449e04a0e810283a1e9933adedd2")

	if !bytes.Equal(key, wantKey) {
		t.Errorf("key  = %x, want %x", key, wantKey)
	}
	if !bytes.Equal(iv, wantIV) {
		t.Errorf("iv   = %x, want %x", iv, wantIV)
	}
	if !bytes.Equal(hp, wantHP) {
		t.Errorf("hp   = %x, want %x", hp, wantHP)
	}
}

func TestAppendQUICVarint(t *testing.T) {
	cases := []struct {
		v    uint64
		want string
	}{
		{0, "00"},
		{63, "3f"},
		{1174, "4496"}, // 2-byte form: 0x4000 | 1174
		{494878333, "9d7f3e7d"},
	}
	for _, c := range cases {
		got := appendQUICVarint(nil, c.v)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("appendQUICVarint(%d) = %x, want %s", c.v, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./device -run 'TestDeriveInitialKeysRFC9001|TestAppendQUICVarint' -v`
Expected: FAIL — `undefined: deriveInitialKeys`, `undefined: appendQUICVarint`.

- [ ] **Step 3: Write the crypto core**

Create `device/obf_imitate_quic.go`:

```go
// SPDX-License-Identifier: MIT

package device

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

// quicV1InitialSalt is the QUIC v1 Initial salt (RFC 9001 §5.2). Public and
// fixed: any observer can derive these keys and read the benign SNI — which is
// the entire point of Id (defeating cheap line-rate SNI filtering).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with the
// "tls13 " label prefix and a zero-length context, as QUIC Initial derivation uses.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, 0x00) // zero-length context
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err) // only fails on absurd length; inputs here are fixed-size
	}
	return out
}

// deriveInitialKeys returns the client Initial AEAD key (16), IV (12), and
// header-protection key (16) for a destination connection ID (RFC 9001 §5.2).
func deriveInitialKeys(dcid []byte) (key, iv, hp []byte) {
	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		panic(err)
	}
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	key = hkdfExpandLabel(clientSecret, "quic key", 16)
	iv = hkdfExpandLabel(clientSecret, "quic iv", 12)
	hp = hkdfExpandLabel(clientSecret, "quic hp", 16)
	return key, iv, hp
}

// newAESGCM builds an AES-128-GCM AEAD (16-byte tag) for the Initial payload.
func newAESGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// headerProtectionMask returns the 5-byte-relevant AES-ECB header-protection
// mask (RFC 9001 §5.4.3): a single AES block over the 16-byte ciphertext sample.
func headerProtectionMask(hp, sample []byte) []byte {
	block, err := aes.NewCipher(hp)
	if err != nil {
		panic(err)
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	return mask
}

// appendQUICVarint appends v in QUIC variable-length integer encoding (RFC 9000 §16).
func appendQUICVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(0x40|(v>>8)), byte(v))
	case v <= 1073741823:
		return append(b, byte(0x80|(v>>24)), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(0xc0|(v>>56)), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./device -run 'TestDeriveInitialKeysRFC9001|TestAppendQUICVarint' -v`
Expected: PASS. The key/iv/hp matching the RFC vectors byte-for-byte proves the whole HKDF chain.

- [ ] **Step 5: Commit**

```bash
git add device/obf_imitate_quic.go device/obf_imitate_quic_test.go
git commit -m "feat(imitate): RFC 9001 QUIC Initial crypto core, RFC-vector locked (Tier 4)"
```

---

## Task 2: TLS 1.3 ClientHello + CRYPTO frame builders

**Files:**
- Modify: `device/obf_imitate_quic.go`
- Test: `device/obf_imitate_quic_test.go` (append)

- [ ] **Step 1: Write the failing test**

Append to `device/obf_imitate_quic_test.go`. The test parses the ClientHello back and asserts the SNI round-trips and the message is structurally a ClientHello. It uses the test-only parser helpers added at the end of this task.

```go
func TestBuildClientHelloSNI(t *testing.T) {
	ch := buildClientHello("example.com")
	if ch[0] != 0x01 {
		t.Fatalf("handshake type = %#x, want ClientHello 0x01", ch[0])
	}
	msgLen := int(ch[1])<<16 | int(ch[2])<<8 | int(ch[3])
	if msgLen != len(ch)-4 {
		t.Errorf("declared length %d != body length %d", msgLen, len(ch)-4)
	}
	if got := clientHelloSNI(t, ch); got != "example.com" {
		t.Errorf("recovered SNI = %q, want example.com", got)
	}
}

func TestBuildCryptoFrame(t *testing.T) {
	frame := buildCryptoFrame([]byte("hello"))
	if frame[0] != 0x06 {
		t.Fatalf("frame type = %#x, want CRYPTO 0x06", frame[0])
	}
	got := cryptoFrameData(t, frame)
	if string(got) != "hello" {
		t.Errorf("CRYPTO data = %q, want hello", got)
	}
}
```

Append the test-only parser helpers (also reused by Task 3's round-trip):

```go
func readQUICVarint(b []byte) (uint64, int) {
	length := 1 << (b[0] >> 6)
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, length
}

func cryptoFrameData(t *testing.T, frame []byte) []byte {
	t.Helper()
	if frame[0] != 0x06 {
		t.Fatalf("not a CRYPTO frame: %#x", frame[0])
	}
	off := 1
	_, n := readQUICVarint(frame[off:]) // offset
	off += n
	clen, n := readQUICVarint(frame[off:]) // length
	off += n
	return frame[off : off+int(clen)]
}

func clientHelloSNI(t *testing.T, ch []byte) string {
	t.Helper()
	if ch[0] != 0x01 {
		t.Fatalf("handshake type = %#x, want ClientHello 0x01", ch[0])
	}
	body := ch[4:]
	p := 2 + 32                 // legacy_version + random
	p += 1 + int(body[p])       // legacy_session_id (u8 vec)
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2 + csLen              // cipher_suites (u16 vec)
	p += 1 + int(body[p])       // compression_methods (u8 vec)
	extTotal := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	end := p + extTotal
	for p < end {
		etype := binary.BigEndian.Uint16(body[p:])
		elen := int(binary.BigEndian.Uint16(body[p+2:]))
		edata := body[p+4 : p+4+elen]
		p += 4 + elen
		if etype == 0x0000 { // server_name
			// list_len(2) | name_type(1)=0 | host_len(2) | host
			nameLen := int(binary.BigEndian.Uint16(edata[3:]))
			return string(edata[5 : 5+nameLen])
		}
	}
	t.Fatal("no SNI extension in ClientHello")
	return ""
}
```

> The test file already imports `encoding/hex`/`bytes`/`testing` from Task 1; add `encoding/binary` to its import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./device -run 'TestBuildClientHello|TestBuildCryptoFrame' -v`
Expected: FAIL — `undefined: buildClientHello`, `undefined: buildCryptoFrame`.

- [ ] **Step 3: Write the builders**

Append to `device/obf_imitate_quic.go`. Add `"crypto/rand"` to its import block.

```go
// --- TLS 1.3 ClientHello (generic, valid; static JA3 — not a browser's; Ib tier) ---

func appendU8Vec(b, body []byte) []byte  { return append(append(b, byte(len(body))), body...) }
func appendU16Vec(b, body []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...)
}
func tlsExtension(extType uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, extType)
	return appendU16Vec(b, data)
}

// buildClientHello returns a complete TLS 1.3 ClientHello handshake message
// (type + u24 length + body) advertising the given SNI. Fixed cipher suites,
// x25519 key share, ALPN h3, and QUIC transport parameters — a clean, parseable
// ClientHello whose JA3 is static (matching a real browser is the deferred Ib tier).
func buildClientHello(sni string) []byte {
	var exts []byte

	// server_name (0x0000): server_name_list{ host_name(0x00) | name }
	sniList := append([]byte{0x00}, binary.BigEndian.AppendUint16(nil, uint16(len(sni)))...)
	sniList = append(sniList, sni...)
	exts = append(exts, tlsExtension(0x0000, appendU16Vec(nil, sniList))...)

	// supported_versions (0x002b): u8 list of [TLS 1.3 = 0x0304]
	exts = append(exts, tlsExtension(0x002b, appendU8Vec(nil, []byte{0x03, 0x04}))...)

	// supported_groups (0x000a): u16 list of [x25519 = 0x001d]
	exts = append(exts, tlsExtension(0x000a, appendU16Vec(nil, []byte{0x00, 0x1d}))...)

	// key_share (0x0033): client_shares{ group(x25519) | key_exchange(32 rand) }
	pub := make([]byte, 32)
	rand.Read(pub)
	ks := append([]byte{0x00, 0x1d}, appendU16Vec(nil, pub)...)
	exts = append(exts, tlsExtension(0x0033, appendU16Vec(nil, ks))...)

	// signature_algorithms (0x000d): ecdsa_p256_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
	exts = append(exts, tlsExtension(0x000d, appendU16Vec(nil, []byte{0x04, 0x03, 0x08, 0x04, 0x04, 0x01}))...)

	// application_layer_protocol_negotiation (0x0010): ["h3"]
	exts = append(exts, tlsExtension(0x0010, appendU16Vec(nil, appendU8Vec(nil, []byte("h3"))))...)

	// quic_transport_parameters (0x0039): initial_source_connection_id (0x0f), empty
	exts = append(exts, tlsExtension(0x0039, []byte{0x0f, 0x00})...)

	body := []byte{0x03, 0x03} // legacy_version = TLS 1.2
	random := make([]byte, 32)
	rand.Read(random)
	body = append(body, random...)
	body = appendU8Vec(body, nil)                                       // legacy_session_id: empty
	body = appendU16Vec(body, []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03}) // cipher_suites
	body = appendU8Vec(body, []byte{0x00})                             // compression: null
	body = appendU16Vec(body, exts)                                    // extensions

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

// buildCryptoFrame wraps data in a QUIC CRYPTO frame (type 0x06) at offset 0.
func buildCryptoFrame(data []byte) []byte {
	b := appendQUICVarint([]byte{0x06}, 0) // type + offset
	b = appendQUICVarint(b, uint64(len(data)))
	return append(b, data...)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./device -run 'TestBuildClientHello|TestBuildCryptoFrame' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add device/obf_imitate_quic.go device/obf_imitate_quic_test.go
git commit -m "feat(imitate): TLS 1.3 ClientHello + CRYPTO frame builders (Tier 4)"
```

---

## Task 3: Assemble the Initial + `qinitObf` adapter (round-trip locked)

**Files:**
- Modify: `device/obf_imitate_quic.go`
- Test: `device/obf_imitate_quic_test.go` (append)

- [ ] **Step 1: Write the failing test (self-decrypt round-trip)**

Append to `device/obf_imitate_quic_test.go`. The decrypt mirrors the build and is the real correctness guard: a wrong header-protection mask or AEAD nonce still yields 1200 plausible bytes, so only a successful decrypt-and-recover-SNI proves the packet is correct.

```go
func TestQInitRoundTrip(t *testing.T) {
	o, err := newQInitObf("example.com")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := o.ObfuscatedLen(0); got != 1200 {
		t.Fatalf("ObfuscatedLen(0) = %d, want 1200", got)
	}
	pkt := make([]byte, o.ObfuscatedLen(0))
	o.Obfuscate(pkt, nil)

	// Structural: long header, fixed bit, Initial type (bits 4-5 = 00).
	if pkt[0]&0xC0 != 0xC0 {
		t.Errorf("byte0 = %#x, want long-header form (0xC0..)", pkt[0])
	}
	if pkt[0]&0x30 != 0x00 {
		t.Errorf("byte0 = %#x, want Initial packet type (bits 4-5 = 0)", pkt[0])
	}
	if v := binary.BigEndian.Uint32(pkt[1:]); v != 1 {
		t.Errorf("version = %#x, want QUIC v1", v)
	}

	if got := decryptInitialSNI(t, pkt); got != "example.com" {
		t.Errorf("round-tripped SNI = %q, want example.com", got)
	}
}

func TestQInitConsecutiveDiffer(t *testing.T) {
	o, _ := newQInitObf("example.com")
	a := make([]byte, 1200)
	b := make([]byte, 1200)
	o.Obfuscate(a, nil)
	o.Obfuscate(b, nil)
	if bytes.Equal(a, b) {
		t.Error("consecutive Initials are byte-identical; crypto/rand fields not varying")
	}
}

func TestNewQInitObfValidation(t *testing.T) {
	if _, err := newQInitObf(""); err == nil {
		t.Error("empty server name must be rejected")
	}
	if _, err := newQInitObf(string(make([]byte, 256))); err == nil {
		t.Error("over-long server name must be rejected")
	}
	o, err := newQInitObf("example.com")
	if err != nil {
		t.Fatalf("valid build: %v", err)
	}
	if o.DeobfuscatedLen(1200) != 0 {
		t.Error("DeobfuscatedLen should be 0 (cosmetic, carries no real payload)")
	}
	if !o.Deobfuscate(nil, nil) {
		t.Error("Deobfuscate should always accept (cosmetic, like randObf)")
	}
}

// decryptInitialSNI parses + unprotects + decrypts a client Initial and returns
// its SNI. Mirrors buildQUICInitial; reuses deriveInitialKeys/headerProtectionMask/
// newAESGCM from the implementation.
func decryptInitialSNI(t *testing.T, pkt []byte) string {
	t.Helper()
	off := 5 // skip byte0 + version(4)
	dcidLen := int(pkt[off])
	off++
	dcid := pkt[off : off+dcidLen]
	off += dcidLen
	scidLen := int(pkt[off])
	off += 1 + scidLen
	tokenLen, n := readQUICVarint(pkt[off:])
	off += n + int(tokenLen)
	_, n = readQUICVarint(pkt[off:]) // length field
	off += n
	pnOffset := off

	key, iv, hp := deriveInitialKeys(dcid)
	mask := headerProtectionMask(hp, pkt[pnOffset+4:pnOffset+4+16])

	first := pkt[0] ^ (mask[0] & 0x0f)
	pnLen := int(first&0x03) + 1
	hdr := make([]byte, pnOffset+pnLen)
	copy(hdr, pkt[:pnOffset+pnLen])
	hdr[0] = first
	pnFull := make([]byte, 4)
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] = pkt[pnOffset+i] ^ mask[1+i]
		pnFull[4-pnLen+i] = hdr[pnOffset+i]
	}

	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 4; i++ {
		nonce[8+i] ^= pnFull[i]
	}
	plaintext, err := newAESGCM(key).Open(nil, nonce, pkt[pnOffset+pnLen:], hdr)
	if err != nil {
		t.Fatalf("GCM open failed (crypto/framing bug): %v", err)
	}
	return clientHelloSNI(t, cryptoFrameData(t, plaintext))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./device -run 'TestQInit|TestNewQInitObf' -v`
Expected: FAIL — `undefined: newQInitObf`.

- [ ] **Step 3: Write the assembler + adapter**

Append to `device/obf_imitate_quic.go`. Add `"errors"` and `"strings"` to its import block.

```go
// --- Full Initial datagram + obf adapter (mechanism C: I-packets) ---

const qinitDatagramLen = 1200 // RFC 9000 §14.1 client-Initial minimum

// buildQUICInitial returns a complete, header-protected QUIC v1 Initial datagram
// of exactly datagramLen bytes carrying a ClientHello with sni. Connection IDs,
// packet number, and the ClientHello randoms come from crypto/rand, so each call
// differs (real-client behavior; no byte-identical signature). datagramLen is
// fixed at 1200, which keeps the QUIC "Length" field a 2-byte varint.
func buildQUICInitial(sni string, datagramLen int) []byte {
	const pnLen = 4
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	pn := make([]byte, pnLen)
	rand.Read(dcid)
	rand.Read(scid)
	rand.Read(pn)

	key, iv, hp := deriveInitialKeys(dcid)
	crypto := buildCryptoFrame(buildClientHello(sni))

	// header = byte0(1) + version(4) + dcidLen(1)+dcid + scidLen(1)+scid
	//          + tokenLen(1) + lengthVarint(2) + pn(pnLen)
	headerLen := 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 2 + pnLen
	payloadLen := datagramLen - headerLen - 16 // 16 = GCM tag; rest is plaintext
	payload := make([]byte, payloadLen)
	copy(payload, crypto) // trailing zeros are PADDING frames (0x00)

	lengthField := pnLen + payloadLen + 16 // covers PN + ciphertext + tag

	hdr := []byte{0xC3} // long header | fixed bit | Initial(00) | pnLen-1 = 3
	hdr = binary.BigEndian.AppendUint32(hdr, 1)
	hdr = appendU8Vec(hdr, dcid)
	hdr = appendU8Vec(hdr, scid)
	hdr = append(hdr, 0x00) // token length 0
	hdr = appendQUICVarint(hdr, uint64(lengthField))
	pnOffset := len(hdr)
	hdr = append(hdr, pn...)

	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < pnLen; i++ {
		nonce[12-pnLen+i] ^= pn[i]
	}
	sealed := newAESGCM(key).Seal(nil, nonce, payload, hdr)

	pkt := make([]byte, 0, datagramLen)
	pkt = append(pkt, hdr...)
	pkt = append(pkt, sealed...)

	// Header protection (RFC 9001 §5.4): sample 16 bytes at pnOffset+4.
	mask := headerProtectionMask(hp, pkt[pnOffset+4:pnOffset+4+16])
	pkt[0] ^= mask[0] & 0x0f // long header: low 4 bits
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

// qinitObf is the obf-registry adapter for Id (mechanism C): each I-packet is a
// fresh, fully-protected QUIC Initial advertising sni. Cosmetic on the wire like
// randObf — a vanilla peer drops it as undecryptable junk.
type qinitObf struct {
	sni    string
	length int
}

// newQInitObf parses the qinit tag value (the SNI) and binds a 1200-byte Initial
// builder. Registered as i1=<qinit example.com>.
func newQInitObf(val string) (obf, error) {
	sni := strings.TrimSpace(val)
	if sni == "" {
		return nil, errors.New("qinit requires a server name, e.g. i1=<qinit example.com>")
	}
	if len(sni) > 255 {
		return nil, errors.New("qinit server name too long (max 255)")
	}
	return &qinitObf{sni: sni, length: qinitDatagramLen}, nil
}

func (o *qinitObf) Obfuscate(dst, src []byte) { copy(dst, buildQUICInitial(o.sni, o.length)) }
func (o *qinitObf) Deobfuscate(dst, src []byte) bool { return true }
func (o *qinitObf) ObfuscatedLen(n int) int          { return o.length }
func (o *qinitObf) DeobfuscatedLen(n int) int         { return 0 }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./device -run 'TestQInit|TestNewQInitObf' -v`
Expected: PASS — the round-trip recovers `example.com`, consecutive packets differ, validation rejects empty/over-long.

- [ ] **Step 5: Commit**

```bash
git add device/obf_imitate_quic.go device/obf_imitate_quic_test.go
git commit -m "feat(imitate): assemble fake QUIC Initial + qinit obf adapter (Tier 4)"
```

---

## Task 4: Register `qinit` in `obfBuilders` + UAPI coverage

**Files:**
- Modify: `device/obf.go:11-26`
- Test: `device/obf_imitate_quic_test.go` (append), `device/uapi_test.go` (append)

- [ ] **Step 1: Write the failing registry + UAPI tests**

Append to `device/obf_imitate_quic_test.go`:

```go
func TestObfChainQInitRegistered(t *testing.T) {
	chain, err := newObfChain("<qinit example.com>")
	if err != nil {
		t.Fatalf("newObfChain: %v", err)
	}
	if got := chain.ObfuscatedLen(0); got != 1200 {
		t.Fatalf("ObfuscatedLen(0) = %d, want 1200", got)
	}
	buf := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(buf, nil) // must not panic
	if got := decryptInitialSNI(t, buf); got != "example.com" {
		t.Errorf("SNI = %q, want example.com", got)
	}
}
```

Append to `device/uapi_test.go` (it already has `randDevice`-based imitate tests):

```go
func TestIpcSetQInitIPacket(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	if err := dev.IpcSet("i1=<qinit example.com>\n"); err != nil {
		t.Fatalf("set i1=<qinit example.com>: %v", err)
	}
	if dev.ipackets[0] == nil {
		t.Fatal("ipackets[0] not set after i1=<qinit example.com>")
	}
	if got := dev.ipackets[0].ObfuscatedLen(0); got != 1200 {
		t.Errorf("qinit ObfuscatedLen(0) = %d, want 1200", got)
	}

	if err := dev.IpcSet("i2=<qinit >\n"); err == nil {
		t.Error("i2=<qinit > (empty SNI) should be rejected")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./device -run 'TestObfChainQInitRegistered|TestIpcSetQInitIPacket' -v`
Expected: FAIL — `newObfChain` joins error `unknown tag <qinit>`.

- [ ] **Step 3: Register the builder**

In `device/obf.go`, add `qinit` to the `obfBuilders` map under the Tier-3 entries:

```go
	// Tier 3 traffic-imitation I-packets (mechanism C): protocol-shaped junk.
	"q":    newImitateObf(imitateQUIC),
	"dns":  newImitateObf(imitateDNS),
	"stun": newImitateObf(imitateSTUN),
	"sip":  newImitateObf(imitateSIP),

	// Tier 4 (Id): fake QUIC Initial carrying a ClientHello + SNI.
	"qinit": newQInitObf,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./device -run 'TestObfChainQInitRegistered|TestIpcSetQInitIPacket' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add device/obf.go device/obf_imitate_quic_test.go device/uapi_test.go
git commit -m "feat(imitate): register qinit I-packet builder + UAPI coverage (Tier 4)"
```

---

## Task 5: Interop anchor test + documentation

**Files:**
- Modify: `device/device_test.go`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add the patched-sender ↔ vanilla-peer interop test**

Append to `device/device_test.go`, mirroring `TestAWGDevicePingImitateIPacket` (`device/device_test.go:~280`) but driving a `qinit` Initial. The Initial is cosmetic junk the vanilla peer drops, so traffic must still pass — that is the interop assertion.

```go
// Run test with -race=false to avoid the race for setting the default msgTypes 2 times
func TestAWGDevicePingImitateQInit(t *testing.T) {
	goroutineLeakCheck(t)

	pair := genTestPair(t, true,
		"h1", "123456-123500",
		"h2", "67543-67550",
		"h3", "123123-123200",
		"h4", "32345-32350",
		"i1", "<qinit example.com>",
	)
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}
```

> Re-read `device/device_test.go:280-303` first and match the `genTestPair(t, true, …)` signature and the h1–h4 values exactly; only the `i1` line changes.

- [ ] **Step 2: Run the interop test to verify it passes**

Run: `go test ./device -run TestAWGDevicePingImitateQInit -v`
Expected: PASS. (If a pre-existing `-race` flake appears as it does for the other imitate ping tests, re-run that single test with `-race=false` per the comment above it.)

- [ ] **Step 3: Document the `qinit` tag**

In `CLAUDE.md`, in the "Traffic imitation" runtime-gotchas bullet, append after the Tier-3 I-packet sentence:

```markdown
  Tier 4 (`Id`) adds `i1=<qinit example.com>`: a single fully-protected 1200-byte
  QUIC v1 Initial carrying a TLS 1.3 ClientHello with that SNI (RFC 9001 well-known
  salt, built with Go std crypto — no uTLS), to defeat cheap line-rate SNI filtering.
  It is cosmetic junk a vanilla peer drops; each datagram uses fresh `crypto/rand`
  connection IDs. Lives in `device/obf_imitate_quic.go`; correctness is locked by the
  RFC 9001 Appendix A.1 key vectors plus a self-decrypt round-trip
  (`device/obf_imitate_quic_test.go`) — there is no `transform.rs` reference for
  long-header Initials. JA3/JA4 fingerprint matching (`Ib`) is a later tier.
```

- [ ] **Step 4: Run the full device suite (includes the gofmt gate)**

Run: `gofmt -l device/ && go test ./device`
Expected: `gofmt -l` prints nothing; `go test ./device` PASS, including `TestFormatting` and the unchanged `TestImitateGoldenVectors` (Tier 4 adds no Tiers 1–3 fill path).

- [ ] **Step 5: Commit**

```bash
git add device/device_test.go CLAUDE.md
git commit -m "test(imitate): interop anchor + docs for qinit Initial (Tier 4)"
```

---

## Self-Review

**Spec coverage (§7.5 "Tier 4 — fake QUIC Initial with SNI (`Id`)"):**
- "Id only, no uTLS" → all crypto is Go std (`crypto/aes`/`cipher`/`hkdf`/`sha256`); no `go.mod` change. Tasks 1–3. ✓
- "Generic valid TLS 1.3 ClientHello" → `buildClientHello` (Task 2): fixed ciphers, x25519, ALPN h3, quic_transport_parameters, + SNI. ✓
- "`crypto/rand` for the random fields" → DCID/SCID/PN/CH-random/key_share all from `rand.Read` (Tasks 2–3); `TestQInitConsecutiveDiffer` asserts variation. ✓
- "`i1=<qinit example.com>`, fixed 1200 B" → `qinitObf` + `qinitDatagramLen = 1200`, registered in Task 4; `ObfuscatedLen(0)=1200`. ✓
- "No separate device-level `imitate_sni` key" → not added; builder is self-contained (Task 4). ✓
- "RFC 9001 v1 well-known salt" → `quicV1InitialSalt` (Task 1), validated by the A.1 vectors. ✓
- "Self-decrypt round-trip replaces golden vectors" → `decryptInitialSNI` + `TestQInitRoundTrip` (Task 3); crypto core additionally locked by RFC 9001 A.1 (Task 1). ✓
- Tier-4 porter-traps (HKDF chain, `"tls13 "` prefix, nonce XOR, AES-ECB sample at pn+4, low-4-bit mask, 2-byte varint, `0xC3` first byte, size accounting) → all realized in Tasks 1 & 3 and guarded by the A.1 + round-trip tests. ✓
- Threat-model honesty (defeats line-rate SNI filtering only; nothing vs a full QUIC state machine; static JA3) → documented in `CLAUDE.md` (Task 5) and spec §7.5. ✓
- `Ib` deferred → stated as out-of-scope; not built. ✓

**Mechanism-C call site:** I-packet path (`device/send.go:131-137`) already does `make([]byte, ipacket.ObfuscatedLen(0))` + `Obfuscate(buf, nil)`; `qinitObf` plugs in via the registry with **no `send.go` edit**, like Tier 3. ✓

**No new Tiers 1–3 golden vectors:** Tier 4 adds a distinct datagram path (`buildQUICInitial`), not a `imitateFillWhole`/`imitateFillPrefix` change, so `TestImitateGoldenVectors` is untouched (re-run in Task 5 to confirm). ✓

**Type consistency:** `newQInitObf(val string) (obf, error)` matches `obfBuilder`; `qinitObf{sni string; length int}` implements `Obfuscate/Deobfuscate/ObfuscatedLen/DeobfuscatedLen` (`obf`, `device/obf.go:22-27`). `deriveInitialKeys(dcid []byte) (key, iv, hp []byte)`, `hkdfExpandLabel(secret []byte, label string, length int) []byte`, `headerProtectionMask(hp, sample []byte) []byte`, `newAESGCM(key []byte) cipher.AEAD`, `appendQUICVarint(b []byte, v uint64) []byte`, `buildClientHello(sni string) []byte`, `buildCryptoFrame(data []byte) []byte`, `buildQUICInitial(sni string, datagramLen int) []byte` — names/signatures identical across the tasks that define and call them, and the test-only helpers (`readQUICVarint`, `cryptoFrameData`, `clientHelloSNI`, `decryptInitialSNI`, `mustHex`) reuse the implementation functions without redefining them. ✓

**Concurrency:** `qinitObf` holds no mutable state (`sni`/`length` are read-only after build); `buildQUICInitial` is a pure function of `(sni, datagramLen)` + `crypto/rand`, so the shared `device.ipackets` `*qinitObf` is safe under concurrent `SendHandshakeInitiation` across peers — no counter needed (unlike `imitateObf`, since `crypto/rand` supplies the per-packet variation). ✓
