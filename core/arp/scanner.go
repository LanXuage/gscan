package arp

import (
	"net"
	"net/netip"
	"time"

	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/receiver"
	"github.com/LanXuage/gscan/scanner"
	mapset "github.com/deckarep/golang-set"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

type ARPScannerCore struct {
	opts      gopacket.SerializeOptions                        // 包序列化选项
	ahMap     cmap.ConcurrentMap[netip.Addr, net.HardwareAddr] // 获取到的IP <-> Mac 映射表
	scanTasks mapset.Set
}

func NewARPScannerCore() scanner.ScannerCore {
	a := &ARPScannerCore{
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		ahMap:     cmap.NewWithCustomShardingFunction[netip.Addr, net.HardwareAddr](common.Fnv32),
		scanTasks: mapset.NewSet(),
	}
	receiver.GetPacketReceiverObserver().AddPacketReceiver(a)
	return a
}

func (a *ARPScannerCore) GenerateTargetByPrefix(iface common.GSIface, prefix netip.Prefix, task scanner.ScanTask) {
	if !a.scanTasks.Contains(task) {
		a.scanTasks.Add(task)
	}
	for i := 0; i < 2; i++ {
		nextAddr := prefix.Addr()
		addrSlice := nextAddr.AsSlice()
		for {
			if (nextAddr.Is4() && addrSlice[3] != 0 && addrSlice[3] != 255) || (nextAddr.Is6() && addrSlice[15] != 0 && (addrSlice[14] != 255 || addrSlice[15] != 255)) {
				if nextAddr.IsValid() && prefix.Contains(nextAddr) && iface.Mask.Contains(nextAddr) {
					if gh, ok := a.ahMap.Get(iface.Gateway); ok {
						prefix1, prefix2 := common.GetOuiPrefix(iface.HWAddr)
						vendor, ok := common.OUI_MAP.Load(prefix2)
						if !ok {
							if vendor, ok = common.OUI_MAP.Load(prefix1); !ok {
								vendor = ""
							}
						}
						task.PutResult(&ARPScanResult{
							IP:     nextAddr,
							Mac:    gh,
							Vendor: vendor.(string),
						})
						return
					}
					task.PutTarget(&ARPScanTarget{
						SrcMac: iface.HWAddr,
						SrcIP:  iface.IP,
						DstIP:  nextAddr,
						Handle: iface.Handle,
					})
				} else {
					break
				}
			}
			if i == 1 {
				nextAddr = nextAddr.Prev()
			} else {
				nextAddr = nextAddr.Next()
			}
			addrSlice = nextAddr.AsSlice()
		}
	}
}

func (a *ARPScannerCore) GenerateTarget(iface common.GSIface, ip netip.Addr, task scanner.ScanTask) {
	if !a.scanTasks.Contains(task) {
		a.scanTasks.Add(task)
	}
	logger.Debug("so", zap.Any("ip", iface.Gateway))
	if gh, ok := a.ahMap.Get(iface.Gateway); ok {
		prefix1, prefix2 := common.GetOuiPrefix(iface.HWAddr)
		vendor, ok := common.OUI_MAP.Load(prefix2)
		if !ok {
			if vendor, ok = common.OUI_MAP.Load(prefix1); !ok {
				vendor = ""
			}
		}
		task.PutResult(&ARPScanResult{
			IP:     ip,
			Mac:    gh,
			Vendor: vendor.(string),
		})
		return
	}
	if iface.Mask.Contains(ip) {
		task.PutTarget(&ARPScanTarget{
			SrcMac: iface.HWAddr,
			SrcIP:  iface.IP,
			DstIP:  ip,
			Handle: iface.Handle,
		})
	}
}

// ARP发包
func (a *ARPScannerCore) Send(iTarget interface{}) {
	target := iTarget.(*ARPScanTarget)
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
	err := gopacket.SerializeLayers(buf, a.opts, ethLayer, arpLayer)
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

func (s *ARPScannerCore) putResult(result *ARPScanResult) {
	s.scanTasks.Each(func(task interface{}) bool {
		task.(scanner.ScanTask).PutResult(result)
		return true
	})
}

// 接收协程
func (a *ARPScannerCore) Receive(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return
	}
	arp, ok := arpLayer.(*layers.ARP)
	if !ok {
		return
	}
	if arp.Operation != layers.ARPReply {
		return
	}
	srcMac := net.HardwareAddr(arp.SourceHwAddress)
	srcIP, _ := netip.AddrFromSlice(arp.SourceProtAddress)
	if result, ok := a.generateResult(srcIP, srcMac); ok {
		a.putResult(result)
	}
	dstMac := net.HardwareAddr(arp.DstHwAddress)
	dstIP, _ := netip.AddrFromSlice(arp.DstProtAddress)
	if result, ok := a.generateResult(dstIP, dstMac); ok {
		a.putResult(result)
	}
}

func (a *ARPScannerCore) generateResult(srcIP netip.Addr, srcMac net.HardwareAddr) (*ARPScanResult, bool) {
	if a.ahMap.SetIfAbsent(srcIP, srcMac) {
		prefix1, prefix2 := common.GetOuiPrefix(srcMac)
		vendor, ok := common.OUI_MAP.Load(prefix2)
		if !ok {
			if vendor, ok = common.OUI_MAP.Load(prefix1); !ok {
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
