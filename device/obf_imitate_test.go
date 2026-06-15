package device

import (
	"encoding/binary"
	"testing"
)

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
		{0, 12345},               // 0*A + C
		{1, 1103527590},          // 1103515245 + 12345
		{0xFFFFFFFF, 3191464396}, // wraparound: must be uint32 modular arithmetic
	}
	for _, c := range cases {
		if got := lcgStep(c.in); got != c.want {
			t.Errorf("lcgStep(%#x) = %d, want %d", c.in, got, c.want)
		}
	}
}

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
