package device

import "testing"

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
