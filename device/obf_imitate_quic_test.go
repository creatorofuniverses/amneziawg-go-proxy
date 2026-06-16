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
