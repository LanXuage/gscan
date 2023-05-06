package arp

import (
	"gscan/common"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map/v2"
)

const (
	REGISTER_NAME = "ARP"
)

var ETH_BROADCAST = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var ARP_BROADCAST = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

var logger = common.GetLogger()
var receiver = common.GetReceiver()

type ARPScanResult struct {
	IP     netip.Addr       `json:"ip"`     // 结果IP
	Mac    net.HardwareAddr `json:"mac"`    // 结果物理地址
	Vendor string           `json:"vendor"` // 结果物理地址厂商
}

type ARPScanResults struct {
	Results []*ARPScanResult
}

type Target struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  netip.Addr       // 发包的源协议IP
	DstIP  netip.Addr       // 目的IP
	Handle *pcap.Handle     // 发包的具体句柄地址
}

func newARPScanner() *ARPScanner {
	a := &ARPScanner{
		Stop: make(chan struct{}),
		Opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		Timeout:  3 * time.Second,
		OMap:     common.GetOui(),
		AMap:     cmap.NewWithCustomShardingFunction[uint32, *net.HardwareAddr](func(key uint32) uint32 { return key }),
		AHMap:    cmap.NewWithCustomShardingFunction[netip.Addr, net.HardwareAddr](common.Fnv32),
		Ifaces:   common.GetActiveInterfaces(),
		Ifas:     common.GetActiveIfaces(),
		TargetCh: make(chan *Target, 10),
		ResultCh: make(chan *ARPScanResult, 10),
	}
	go a.Recv()
	go a.Scan()
	for _, iface := range *a.Ifas {
		a.TargetCh <- &Target{
			SrcMac: iface.HWAddr,
			SrcIP:  iface.IP,
			DstIP:  iface.Gateway,
			Handle: iface.Handle,
		}
		for res := range a.ResultCh {
			if iface.Gateway == res.IP {
				break
			}
		}
	}
	return a
}

var instance = newARPScanner()

func GetARPScanner() *ARPScanner {
	return instance
}
