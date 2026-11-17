package webhook

import (
	"strings"
	"testing"
)

func TestNormalizeRecordName(t *testing.T) {
	for _, name := range []string{"vpn.example.com", "VPN.Example.COM."} {
		got, err := NormalizeRecordName(name)
		if err != nil || got != "vpn.example.com" {
			t.Fatal("valid name was not normalized")
		}
	}
	for _, name := range []string{"", "localhost", "*.example.com", "-vpn.example.com", "vpn-.example.com", "vpn..example.com", "vpn.example.com..", "vpn.example.com ", "vpn_example.com", strings.Repeat("a", 64) + ".example.com", strings.Repeat("a.", 127) + "com"} {
		if _, err := NormalizeRecordName(name); err == nil {
			t.Fatalf("invalid name accepted: %q", name)
		}
	}
}
