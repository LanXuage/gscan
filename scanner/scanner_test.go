package scanner_test

import (
	"net/netip"
	"testing"
)

func TestPrefix(t *testing.T) {
	prefix, _ := netip.ParsePrefix("192.168.1.0/24")
	prefix2, _ := netip.ParsePrefix("192.168.1.0/20")
	t.Log(prefix2.Contains(prefix.Addr()))
	t.Log(prefix.Addr().Next())
}
