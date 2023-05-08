//go:build windows

package common

import (
	"net"
	"net/netip"
)

func Gways() []netip.Addr {
	return nil
}

// Deprecated: Use common.Gways instead.
func GetGateways() []net.IP {
	return nil
}
