package arp

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/LanXuage/gscan/common"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

type ARPScanner struct {
	common.IScanner
	Opts  gopacket.SerializeOptions                        // 包序列化选项
	Ifas  *[]common.GSIface                                // 可用接口列表
	AHMap cmap.ConcurrentMap[netip.Addr, net.HardwareAddr] // 获取到的IP <-> Mac 映射表
	OMap  *sync.Map                                        // Mac前缀 <-> 厂商 映射表
}

func (a *ARPScanner) Close() {
	defer receiver.Unregister(REGISTER_NAME)
}

func (a *ARPScanner) Init(s *common.Scanner) {
	go a.goRecv(s.ResultCh)
	go a.goScan(s.TargetCh)
	for _, iface := range *a.Ifas {
		if iface.Gateway == iface.IP {
			continue
		}
		s.TargetCh <- &Target{
			SrcMac: iface.HWAddr,
			SrcIP:  iface.IP,
			DstIP:  iface.Gateway,
			Handle: iface.Handle,
		}
		timeoutCh := make(chan struct{})
		go func(timeoutCh chan struct{}, timeout time.Duration) {
			defer close(timeoutCh)
			time.Sleep(timeout)
		}(timeoutCh, 6*time.Second)
	L1:
		for {
			select {
			case res := <-s.ResultCh:
				if iface.Gateway == res.(*ARPScanResult).IP {
					break L1
				}
			case <-timeoutCh:
				logger.Panic("Get gateway's hardwareaddr failed. ", zap.Any("iface", iface))
			}
		}
	}
}

func (a *ARPScanner) GenerateTargetByPrefix(prefix netip.Prefix, iface common.GSIface, s *common.Scanner) {
	for i := 0; i < 2; i++ {
		nIP := prefix.Addr()
		for {
			if (nIP.Is4() && nIP.AsSlice()[3] != 0 && nIP.AsSlice()[3] != 255) || (nIP.Is6() && nIP.AsSlice()[15] != 0 && (nIP.AsSlice()[14] != 255 || nIP.AsSlice()[15] != 255)) {
				if iface.Gateway == nIP {
					if gh, ok := a.AHMap.Get(iface.Gateway); ok {
						prefix1, prefix2 := common.GetOuiPrefix(iface.HWAddr)
						vendor, ok := a.OMap.Load(prefix2)
						if !ok {
							if vendor, ok = a.OMap.Load(prefix1); !ok {
								vendor = ""
							}
						}
						logger.Debug("generateTargetByPrefix", zap.Any("ret->mac", gh))
						s.ResultCh <- &ARPScanResult{
							IP:     nIP,
							Mac:    gh,
							Vendor: vendor.(string),
						}
					} else {
						s.TargetCh <- &Target{
							SrcMac: iface.HWAddr,
							SrcIP:  iface.IP,
							DstIP:  nIP,
							Handle: iface.Handle,
						}
					}
				} else if !nIP.IsValid() || !prefix.Contains(nIP) || !iface.Mask.Contains(nIP) {
					break
				} else {
					s.TargetCh <- &Target{
						SrcMac: iface.HWAddr,
						SrcIP:  iface.IP,
						DstIP:  nIP,
						Handle: iface.Handle,
					}
				}
			}
			if i == 1 {
				nIP = nIP.Prev()
			} else {
				nIP = nIP.Next()
			}
		}
	}
}

func (a *ARPScanner) GenerateTarget(ip netip.Addr, iface common.GSIface, s *common.Scanner) {
	logger.Debug("so", zap.Any("ip", iface.Gateway))
	if iface.Gateway == ip {
		if gh, ok := a.AHMap.Get(iface.Gateway); ok {
			prefix1, prefix2 := common.GetOuiPrefix(iface.HWAddr)
			vendor, ok := a.OMap.Load(prefix2)
			if !ok {
				if vendor, ok = a.OMap.Load(prefix1); !ok {
					vendor = ""
				}
			}
			logger.Debug("goScanMany", zap.Any("ret->mac", gh))
			s.ResultCh <- &ARPScanResult{
				IP:     ip,
				Mac:    gh,
				Vendor: vendor.(string),
			}
			return
		}
	}
	if iface.Mask.Contains(ip) {
		s.TargetCh <- &Target{
			SrcMac: iface.HWAddr,
			SrcIP:  iface.IP,
			DstIP:  ip,
			Handle: iface.Handle,
		}
	}
}

// 接收协程
func (a *ARPScanner) goRecv(resultCh chan interface{}) {
	for r := range receiver.Register(REGISTER_NAME, a.RecvARP) {
		if results, ok := r.(ARPScanResults); ok {
			for _, result := range results.Results {
				resultCh <- result
			}
		}
	}
}

// 扫描协程
func (a *ARPScanner) goScan(targetCh chan interface{}) {
	for target := range targetCh {
		a.SendARPReq(target.(*Target))
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
	time.Sleep(time.Microsecond * 1001)
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
	if a.AHMap.SetIfAbsent(srcIP, srcMac) {
		prefix1, prefix2 := common.GetOuiPrefix(srcMac)
		vendor, ok := a.OMap.Load(prefix2)
		if !ok {
			if vendor, ok = a.OMap.Load(prefix1); !ok {
				vendor = ""
			}
		}
		logger.Debug("generateResult", zap.Any("ret->mac", srcMac))
		result := &ARPScanResult{
			IP:     srcIP,
			Mac:    srcMac,
			Vendor: vendor.(string),
		}
		return result, true
	}
	return nil, false
}
