package arp

import (
	"net"
	"net/netip"

	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/scanner"

	"github.com/google/gopacket/pcap"
)

const (
	REGISTER_NAME = "ARP"
)

var ETH_BROADCAST = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var ARP_BROADCAST = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

var logger = common.GetLogger()

type ARPScanResult struct {
	IP     netip.Addr       `json:"ip"`     // 结果IP
	Mac    net.HardwareAddr `json:"mac"`    // 结果物理地址
	Vendor string           `json:"vendor"` // 结果物理地址厂商
}

type ARPScanTarget struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  netip.Addr       // 发包的源协议IP
	DstIP  netip.Addr       // 目的IP
	Handle *pcap.Handle     // 发包的具体句柄地址
}

func newARPScanner() scanner.Scanner {
	return scanner.NewScanner(NewARPScannerCore())
}

var instance scanner.Scanner

func init() {
	instance = newARPScanner()
}

func GetARPScanner() scanner.Scanner {
	return instance
}

func GetMac(ip netip.Addr) (*net.HardwareAddr, bool) {
	for result := range instance.Scan([]netip.Addr{ip}).GetResults(10) {
		tmp := result.(*ARPScanResult)
		if tmp.IP == ip {
			return &tmp.Mac, true
		}
	}
	return nil, false
}
