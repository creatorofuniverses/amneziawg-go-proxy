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

	// STUN: Binding Success Response, magic cookie, advertised length == written TLV bytes.
	// Per transform.rs: the header advertises `written` (TLV bytes actually filled),
	// not `body` (the full aligned body). For n=600: XOR-MAPPED-ADDRESS(12) +
	// SOFTWARE-header(4) + SOFTWARE-value(capped at 124) = 140.
	s := make([]byte, n)
	imitateFillWhole(s, imitateJunkSeed(7), imitateSTUN)
	if binary.BigEndian.Uint16(s[0:2]) != 0x0101 {
		t.Errorf("STUN type = %#x, want 0x0101", s[0:2])
	}
	if binary.BigEndian.Uint32(s[4:8]) != 0x2112A442 {
		t.Errorf("STUN cookie = %#x, want 0x2112A442", s[4:8])
	}
	// XOR-MAPPED-ADDRESS (12) + SOFTWARE header (4) + value capped at 124.
	wantSTUNLen := 12 + 4 + 124
	if int(binary.BigEndian.Uint16(s[2:4])) != wantSTUNLen {
		t.Errorf("STUN length = %d, want %d (== written TLV bytes)", binary.BigEndian.Uint16(s[2:4]), wantSTUNLen)
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
