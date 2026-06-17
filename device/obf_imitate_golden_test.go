package device

import (
	"bufio"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

func protoFromName(name string) (imitateProto, bool) {
	switch name {
	case "quic":
		return imitateQUIC, true
	case "dns":
		return imitateDNS, true
	case "stun":
		return imitateSTUN, true
	case "sip":
		return imitateSIP, true
	}
	return imitateNone, false
}

// TestImitateGoldenVectors enforces byte-exactness against transform.rs output.
// Each line: "<proto> <pad> <payload_hex> <output_hex>".
func TestImitateGoldenVectors(t *testing.T) {
	f, err := os.Open("testdata/imitate_vectors.txt")
	if err != nil {
		t.Fatalf("open fixture: %v (regenerate per Task 6 Step 2)", err)
	}
	defer f.Close()

	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[1] == "whole" {
			proto, ok := protoFromName(fields[0])
			if !ok {
				t.Fatalf("unknown proto %q", fields[0])
			}
			length, err := strconv.Atoi(fields[2])
			if err != nil {
				t.Fatalf("bad len %q: %v", fields[2], err)
			}
			seed64, err := strconv.ParseUint(fields[3], 16, 32)
			if err != nil {
				t.Fatalf("bad seed hex %q: %v", fields[3], err)
			}
			want, err := hex.DecodeString(fields[4])
			if err != nil {
				t.Fatalf("bad output hex: %v", err)
			}
			buf := make([]byte, length)
			imitateFillWhole(buf, uint32(seed64), proto)
			if hex.EncodeToString(buf) != hex.EncodeToString(want) {
				t.Errorf("%s whole len=%d: byte mismatch\n got %x\nwant %x", fields[0], length, buf, want)
			}
			n++
			continue
		}
		if len(fields) != 4 {
			t.Fatalf("malformed fixture line: %q", line)
		}
		proto, ok := protoFromName(fields[0])
		if !ok {
			t.Fatalf("unknown proto %q", fields[0])
		}
		pad, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("bad pad %q: %v", fields[1], err)
		}
		payload, err := hex.DecodeString(fields[2])
		if err != nil {
			t.Fatalf("bad payload hex: %v", err)
		}
		want, err := hex.DecodeString(fields[3])
		if err != nil {
			t.Fatalf("bad output hex: %v", err)
		}

		buf := make([]byte, pad+len(payload))
		copy(buf[pad:], payload)
		imitateFillPrefix(buf, pad, proto)

		if hex.EncodeToString(buf) != hex.EncodeToString(want) {
			t.Errorf("%s pad=%d: byte mismatch\n got %x\nwant %x", fields[0], pad, buf, want)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no vectors loaded")
	}
	t.Logf("verified %d golden vectors", n)
}
