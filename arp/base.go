package arp

import (
	"net"
	"net/netip"
	"time"

	"github.com/LanXuage/gscan/common"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
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
		Opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		OMap:  common.GetOui(),
		AHMap: cmap.NewWithCustomShardingFunction[netip.Addr, net.HardwareAddr](common.Fnv32),
		Ifas:  common.GetActiveIfaces(),
		Scanner: common.Scanner{
			Timeout:  3 * time.Second,
			TargetCh: make(chan interface{}, 10),
			ResultCh: make(chan interface{}, 10),
		},
	}
	go a.Recv()
	go a.Scan()
	for _, iface := range *a.Ifas {
		if iface.Gateway == iface.IP {
			continue
		}
		a.TargetCh <- &Target{
			SrcMac: iface.HWAddr,
			SrcIP:  iface.IP,
			DstIP:  iface.Gateway,
			Handle: iface.Handle,
		}
		timeoutCh := make(chan struct{})
		go func(timeoutCh chan struct{}, timeout time.Duration) {
			defer close(timeoutCh)
			time.Sleep(timeout)
		}(timeoutCh, a.Timeout)
	L1:
		for {
			select {
			case res := <-a.ResultCh:
				if iface.Gateway == res.(*ARPScanResult).IP {
					break L1
				}
			case <-timeoutCh:
				logger.Panic("Get gateway's hardwareaddr failed. ", zap.Any("iface", iface))
			}
		}
	}
	return a
}

var instance = newARPScanner()

func GetARPScanner() *ARPScanner {
	return instance
}
