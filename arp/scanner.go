package arp

import (
	"gscan/common"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

type ARPScanner struct {
	// Deprecated: No longer available.
	Stop    chan struct{}             // ARP 扫描器状态
	Opts    gopacket.SerializeOptions // 包序列化选项
	Timeout time.Duration             // 抓包超时时间
	// Deprecated: Use Ifas instead.
	Ifaces *[]common.GSInterface // 可用接口列表
	Ifas   *[]common.GSIface     // 可用接口列表
	// Deprecated: Use AHMap instead.
	AMap     cmap.ConcurrentMap[uint32, *net.HardwareAddr]    // 获取到的IP <-> Mac 映射表
	AHMap    cmap.ConcurrentMap[netip.Addr, net.HardwareAddr] // 获取到的IP <-> Mac 映射表
	OMap     map[string]string                                // Mac前缀 <-> 厂商 映射表
	Lock     sync.Mutex
	TargetCh chan *Target
	ResultCh chan *ARPScanResult
}

func (a *ARPScanner) Close() {
	receiver.Unregister(REGISTER_NAME)
	close(a.TargetCh)
	close(a.ResultCh)
}

func (a *ARPScanner) generateTargetByPrefix(prefix netip.Prefix, iface common.GSIface) {
	for i := 0; i < 2; i++ {
		nIp := prefix.Addr()
		for {
			if (nIp.Is4() && nIp.AsSlice()[3] != 0) || (nIp.Is6() && nIp.AsSlice()[15] != 0) {
				if iface.Gateway == nIp {
					prefix1, prefix2 := common.GetOuiPrefix(iface.HWAddr)
					vendor := a.OMap[prefix2]
					if len(vendor) == 0 {
						vendor = a.OMap[prefix1]
					}
					gh, _ := a.AHMap.Get(iface.Gateway)
					a.ResultCh <- &ARPScanResult{
						IP:     nIp,
						Mac:    gh,
						Vendor: vendor,
					}
				} else if !nIp.IsValid() || !prefix.Contains(nIp) || !iface.Mask.Contains(nIp) {
					break
				} else {
					a.TargetCh <- &Target{
						SrcMac: iface.HWAddr,
						SrcIP:  iface.IP,
						DstIP:  nIp,
						Handle: iface.Handle,
					}
				}
			}
			if i == 1 {
				nIp = nIp.Prev()
			} else {
				nIp = nIp.Next()
			}
		}
	}
}

// 目标生产协程
func (a *ARPScanner) GenerateTarget(timeoutCh chan struct{}) {
	for _, iface := range *a.Ifas {
		a.generateTargetByPrefix(iface.Mask, iface)
	}
	time.Sleep(a.Timeout)
	close(timeoutCh)
}

func (a *ARPScanner) goScanPrefix(prefix netip.Prefix, timetouCh chan struct{}) {
	for _, iface := range *a.Ifas {
		if iface.Mask.Contains(prefix.Addr()) {
			a.generateTargetByPrefix(prefix, iface)
		}
	}
	time.Sleep(a.Timeout)
	close(timetouCh)
}

func (a *ARPScanner) ScanPrefix(prefix netip.Prefix) chan struct{} {
	timeoutCh := make(chan struct{})
	go a.goScanPrefix(prefix, timeoutCh)
	return timeoutCh
}

func (a *ARPScanner) goScanMany(ips []netip.Addr, timeoutCh chan struct{}) {
	for _, ip := range ips {
		for _, iface := range *a.Ifas {
			logger.Debug("so", zap.Any("ip", iface.Gateway))
			if iface.Gateway == ip {
				prefix1, prefix2 := common.GetOuiPrefix(iface.HWAddr)
				vendor := a.OMap[prefix2]
				if len(vendor) == 0 {
					vendor = a.OMap[prefix1]
				}
				gh, _ := a.AHMap.Get(iface.Gateway)
				a.ResultCh <- &ARPScanResult{
					IP:     ip,
					Mac:    gh,
					Vendor: vendor,
				}
			} else if iface.Mask.Contains(ip) {
				a.TargetCh <- &Target{
					SrcMac: iface.HWAddr,
					SrcIP:  iface.IP,
					DstIP:  ip,
					Handle: iface.Handle,
				}
				break
			}
		}
	}
	time.Sleep(a.Timeout)
	close(timeoutCh)
}

func (a *ARPScanner) ScanMany(ips []netip.Addr) chan struct{} {
	timeoutCh := make(chan struct{})
	go a.goScanMany(ips, timeoutCh)
	return timeoutCh
}

// 执行全局域网扫描
func (a *ARPScanner) ScanLocalNet() chan struct{} {
	logger.Debug("Start Generate")
	// logger.Sync()
	timeoutCh := make(chan struct{})
	go a.GenerateTarget(timeoutCh)
	return timeoutCh
}

// 接收协程
func (a *ARPScanner) Recv() {
	defer close(a.ResultCh)
	for r := range receiver.Register(REGISTER_NAME, a.RecvARP) {
		if results, ok := r.(ARPScanResults); ok {
			for _, result := range results.Results {
				a.ResultCh <- result
			}
		}
	}
}

// 扫描协程
func (a *ARPScanner) Scan() {
	defer close(a.Stop)
	for target := range a.TargetCh {
		a.SendARPReq(target)
	}
}

// ARP发包
func (a *ARPScanner) SendARPReq(target *Target) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       target.SrcMac,
		DstMAC:       ETH_BROADCAST,
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		HwAddressSize:     0x6,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   target.SrcMac,
		SourceProtAddress: target.SrcIP.AsSlice(),
		DstHwAddress:      ARP_BROADCAST,
		DstProtAddress:    target.DstIP.AsSlice(),
	}
	if target.SrcIP.Is4() {
		arpLayer.ProtAddressSize = 0x4
		arpLayer.Protocol = layers.EthernetTypeIPv4
	} else {
		arpLayer.ProtAddressSize = 0x16
		arpLayer.Protocol = layers.EthernetTypeIPv6
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, a.Opts, ethLayer, arpLayer)
	if err != nil {
		logger.Error("SerializeLayers Failed", zap.Error(err))
	}
	outgoingPacket := buf.Bytes()
	err = target.Handle.WritePacketData(outgoingPacket)
	if err != nil {
		logger.Error("WritePacketData Failed", zap.Error(err))
	}
}

// 接收协程
func (a *ARPScanner) RecvARP(packet gopacket.Packet) interface{} {
	result := ARPScanResults{
		Results: make([]*ARPScanResult, 0),
	}
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return result
	}
	arp, ok := arpLayer.(*layers.ARP)
	if !ok {
		return result
	}
	if arp.Operation != layers.ARPReply {
		return result
	}
	srcMac := net.HardwareAddr(arp.SourceHwAddress)
	srcIP, _ := netip.AddrFromSlice(arp.SourceProtAddress)
	if r, ok := a.generateResult(srcIP, srcMac); ok {
		result.Results = append(result.Results, r)
	}
	dstMac := net.HardwareAddr(arp.DstHwAddress)
	dstIP, _ := netip.AddrFromSlice(arp.DstProtAddress)
	if r, ok := a.generateResult(dstIP, dstMac); ok {
		result.Results = append(result.Results, r)
	}
	return result
}

func (a *ARPScanner) generateResult(srcIP netip.Addr, srcMac net.HardwareAddr) (*ARPScanResult, bool) {
	srcIPU32 := common.IP2Uint32(srcIP.AsSlice())
	if _, ok := a.AHMap.Get(srcIP); !ok {
		prefix1, prefix2 := common.GetOuiPrefix(srcMac)
		vendor := a.OMap[prefix2]
		if len(vendor) == 0 {
			vendor = a.OMap[prefix1]
		}
		result := &ARPScanResult{
			IP:     srcIP,
			Mac:    srcMac,
			Vendor: vendor,
		}
		a.AMap.Set(srcIPU32, &srcMac)
		a.AHMap.Set(srcIP, srcMac)
		return result, true
	}
	return nil, false
}
