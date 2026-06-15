package device

import "testing"

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
