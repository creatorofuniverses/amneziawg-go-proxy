package device

import (
	"strings"
	"testing"
)

func TestUAPIImitateProtocol(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	if err := dev.IpcSet("imitate_protocol=quic\n"); err != nil {
		t.Fatalf("set imitate_protocol=quic: %v", err)
	}
	if got := imitateProto(dev.imitate.proto.Load()); got != imitateQUIC {
		t.Errorf("proto = %d, want imitateQUIC(%d)", got, imitateQUIC)
	}

	if err := dev.IpcSet("imitate_protocol=ftp\n"); err == nil {
		t.Error("imitate_protocol=ftp should be rejected")
	}
}

func TestIpcSetImitateIPacket(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	if err := dev.IpcSet("i1=<q 600>\n"); err != nil {
		t.Fatalf("set i1=<q 600>: %v", err)
	}
	if dev.ipackets[0] == nil {
		t.Fatal("ipackets[0] not set after i1=<q 600>")
	}
	if got := dev.ipackets[0].ObfuscatedLen(0); got != 600 {
		t.Errorf("i1 ObfuscatedLen(0) = %d, want 600", got)
	}

	if err := dev.IpcSet("i2=<q notanumber>\n"); err == nil {
		t.Error("i2=<q notanumber> should be rejected (bad length)")
	}
}

func TestUAPIImitateProtocolRoundTrip(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	if err := dev.IpcSet("imitate_protocol=quic\n"); err != nil {
		t.Fatalf("set imitate_protocol=quic: %v", err)
	}
	out, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(out, "imitate_protocol=quic") {
		t.Errorf("IpcGet output missing imitate_protocol=quic; got:\n%s", out)
	}
}
