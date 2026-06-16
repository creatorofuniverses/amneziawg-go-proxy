// SPDX-License-Identifier: MIT

package device

import (
	"bytes"
	"encoding/binary"
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
		{1073741824, "c000000040000000"},
	}
	for _, c := range cases {
		got := appendQUICVarint(nil, c.v)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("appendQUICVarint(%d) = %x, want %s", c.v, got, c.want)
		}
	}
}

func TestBuildClientHelloSNI(t *testing.T) {
	scid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ch := buildClientHello("example.com", scid)
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
	// initial_source_connection_id transport param must carry the SCID (RFC 9000 §7.3).
	wantISCID := append([]byte{0x0f, byte(len(scid))}, scid...)
	if !bytes.Contains(ch, wantISCID) {
		t.Error("ClientHello quic_transport_parameters missing initial_source_connection_id = SCID")
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
	if len(frame) < 2 {
		t.Fatalf("cryptoFrameData: frame too short (%d bytes)", len(frame))
	}
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
	if len(ch) < 4 {
		t.Fatalf("clientHelloSNI: buffer too short (%d bytes)", len(ch))
	}
	if ch[0] != 0x01 {
		t.Fatalf("handshake type = %#x, want ClientHello 0x01", ch[0])
	}
	body := ch[4:]
	p := 2 + 32           // legacy_version + random
	p += 1 + int(body[p]) // legacy_session_id (u8 vec)
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2 + csLen        // cipher_suites (u16 vec)
	p += 1 + int(body[p]) // compression_methods (u8 vec)
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

	// HP masking only XORs bits 3-0 of byte0, so these high-bit checks reflect the
	// pre-protection 0xC3; the real end-to-end guard is decryptInitialSNI below.
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
