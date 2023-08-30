package icmp

import (
	"net"
	"net/netip"

	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/core/arp"
	"github.com/LanXuage/gscan/scanner"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

var logger *zap.Logger

func init() {
	logger = common.GetLogger()
}

type ICMPTarget struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  netip.Addr       // 发包的源协议IP
	DstIP  netip.Addr       // 目的IP
	DstMac net.HardwareAddr // 目的Mac
	Handle *pcap.Handle     // 发包的具体句柄地址
}

type ICMPScanResult struct {
	arp.ARPScanResult
	IsActive bool // 是否存活
}

type ICMPResultMap *cmap.ConcurrentMap[string, bool]

func NewICMPScanner() scanner.Scanner {
	icmpScanner := &ICMPScannerCore{
		Results: rMap,
		IPList:  []netip.Addr{},
	}
	return scanner.NewScanner(icmpScanner)
}
