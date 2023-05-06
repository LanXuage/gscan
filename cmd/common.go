package cmd

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
)

func ParseAddr(s string) ([]netip.Addr, error) {
	if i := strings.IndexByte(s, '-'); i != -1 {
		ip, _ := netip.ParseAddr(s[:i])
		end, err := strconv.ParseUint(s[i+1:], 10, 8)
		if err != nil {
			end, err = strconv.ParseUint(s[i+1:], 16, 16)
		}
		if err == nil {
			var start uint16
			slice := ip.AsSlice()
			if ip.Is6() {
				start = uint16((uint16(slice[14]) << 8) + uint16(slice[15]))
			} else {
				start = uint16(slice[3])
			}
			ret := []netip.Addr{ip}
			for ; start < uint16(end); start++ {
				ip = ip.Next()
				ret = append(ret, ip)
			}
			return ret, nil
		}
	}
	return nil, fmt.Errorf("unsupported IP format: %s", s)
}

func ParsePort(s string) ([]layers.TCPPort, error) {
	if i := strings.IndexByte(s, '-'); i != -1 {
		start, err := strconv.ParseUint(s[:i], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("unsupported PORT format: %s", s)
		}
		end, err := strconv.ParseUint(s[i+1:], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("unsupported PORT format: %s", s)
		}
		ret := []layers.TCPPort{}
		for ; start < end; start++ {
			ret = append(ret, layers.TCPPort(start))
		}
		return ret, nil
	} else if p, err := strconv.ParseUint(s, 10, 16); err == nil {
		return []layers.TCPPort{layers.TCPPort(p)}, nil
	}
	return nil, fmt.Errorf("unsupported PORT format: %s", s)
}
