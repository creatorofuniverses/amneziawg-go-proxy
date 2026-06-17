package device

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// TestGenWholeVectors is a generator, not an assertion. Run explicitly:
//
//	go test ./device/ -run TestGenWholeVectors -gen-whole
//
// It appends `<proto> whole <len> <seed_hex> <output_hex>` rows to the fixture.
func TestGenWholeVectors(t *testing.T) {
	if os.Getenv("IMITATE_GEN_WHOLE") == "" {
		t.Skip("set IMITATE_GEN_WHOLE=1 to (re)generate whole vectors")
	}
	protos := []struct {
		name string
		p    imitateProto
	}{{"quic", imitateQUIC}, {"dns", imitateDNS}, {"stun", imitateSTUN}, {"sip", imitateSIP}}
	lens := []int{10, 16, 20, 32, 40, 64, 150, 200}
	counters := []uint64{1, 2, 3, 7, 42, 1000}

	f, err := os.OpenFile("testdata/imitate_vectors.txt", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, pr := range protos {
		for _, ln := range lens {
			for _, c := range counters {
				seed := imitateJunkSeed(c)
				buf := make([]byte, ln)
				imitateFillWhole(buf, seed, pr.p)
				fmt.Fprintf(f, "%s whole %d %08x %s\n", pr.name, ln, seed, hex.EncodeToString(buf))
			}
		}
	}
}
