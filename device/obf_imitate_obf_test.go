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

func TestObfChainImitateRegistered(t *testing.T) {
	for _, tag := range []string{"q", "dns", "stun", "sip"} {
		spec := "<" + tag + " 600>"
		chain, err := newObfChain(spec)
		if err != nil {
			t.Fatalf("%s: newObfChain(%q): %v", tag, spec, err)
		}
		if got := chain.ObfuscatedLen(0); got != 600 {
			t.Errorf("%s: ObfuscatedLen(0) = %d, want 600", tag, got)
		}
		buf := make([]byte, chain.ObfuscatedLen(0))
		chain.Obfuscate(buf, nil) // must not panic; fills the whole datagram
	}
}
