package device

import "testing"

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
