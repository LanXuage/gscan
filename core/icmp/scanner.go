package icmp

import (
	"log"
	"net/netip"

	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/common/constant"
	"github.com/LanXuage/gscan/core/arp"
	"github.com/LanXuage/gscan/scanner"

	mapset "github.com/deckarep/golang-set"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
)

type ICMPScannerCore struct {
	opts      gopacket.SerializeOptions // 包序列化选项
	scanTasks mapset.Set
}

func NewICMPScannerCore() scanner.ScannerCore {

}

func (icmp *ICMPScannerCore) GenerateTarget(iface common.GSIface, ip netip.Addr, task scanner.ScanTask) {
	if dstMac, ok := arp.GetMac(iface.Gateway); ok {
		task.PutTarget(&ICMPTarget{
			SrcIP:  iface.IP,
			DstIP:  ip,
			SrcMac: iface.HWAddr,
			Handle: iface.Handle,
			DstMac: *dstMac,
		})
	}
}

func (icmp *ICMPScannerCore) GenerateTargetByPrefix(iface common.GSIface, prefix netip.Prefix, task ScanTask) {
	for i := 0; i < 2; i++ {
		nextAddr := prefix.Addr()
		for {
			if (nIp.Is4() && nIp.AsSlice()[3] != 0 && nIp.AsSlice()[3] != 255) || (nIp.Is6() && nIp.AsSlice()[15] != 0 && (nIp.AsSlice()[14] != 255 || nIp.AsSlice()[15] != 255)) {
				if !nIp.IsValid() || !prefix.Contains(nIp) {
					break
				} else {
					icmp.GenerateTarget(iface, nextAddr, task)
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

// ICMP发包
func (icmpScanner *ICMPScanner) Send(target interface{}) {
	payload := []byte("1") // 特征
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	// 构建以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC: target.SrcMac,
		DstMAC: target.DstMac,
	}

	if target.SrcIP.Is4() {
		ethLayer.EthernetType = layers.EthernetTypeIPv4
		ipLayer := &layers.IPv4{
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    target.SrcIP.AsSlice(),
			DstIP:    target.DstIP.AsSlice(),
			Version:  4,
			Flags:    layers.IPv4DontFragment,
			TTL:      64,
		}

		icmpLayer := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, layers.ICMPv4CodeNet),
			Id:       constant.ICMPId,
			Seq:      constant.ICMPSeq,
		}

		// 合并数据包并进行序列化
		err := gopacket.SerializeLayers(
			buffer,
			opts,
			ethLayer,
			ipLayer,
			icmpLayer,
			gopacket.Payload(payload),
		)

		if err != nil {
			logger.Error("Combine Buffer Error", zap.Error(err))
		}

		logger.Sugar().Debugf("Ping IP: %s", target.DstIP.String())

		err = target.Handle.WritePacketData(buffer.Bytes())
		if err != nil {
			log.Fatal(err)
		}

	} else {
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

}

func (icmpScanner *ICMPScanner) goScan(targetCh chan interface{}) {
	for target := range targetCh {
		icmpScanner.SendICMP(target.(*ICMPTarget))
	}
}

// 接收协程
func (icmpScanner *ICMPScanner) goRecv(resultCh chan interface{}) {
	for r := range common.GetReceiver().Register(constant.ICMPREGISTER_NAME, icmpScanner.RecvICMP) {
		if result, ok := r.(ICMPScanResult); ok {
			resultCh <- &result
		}
	}
}

// ICMP接包协程
func (icmpScanner *ICMPScanner) RecvICMP(packet gopacket.Packet) interface{} {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return nil
	}
	icmp, _ := icmpLayer.(*layers.ICMPv4)
	if icmp == nil {
		return nil
	}

	if icmp.Id == constant.ICMPId &&
		icmp.Seq == constant.ICMPSeq {
		if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply &&
			icmp.TypeCode.Code() == layers.ICMPv4CodeNet {
			ip := common.PacketToIPv4(packet)
			if ip != nil {
				if _, ok := (*icmpScanner.Results).Get(ip.To4().String()); !ok {
					(*icmpScanner.Results).Set(ip.To4().String(), true)

					_ip, _ := netip.AddrFromSlice(ip)
					return ICMPScanResult{
						ARPScanResult: arp.ARPScanResult{
							IP: _ip,
						},
						IsActive: true,
					}
				}
			}
		}
	}
	return nil
}

var icmpInstance = newICMPScanner()

func GetICMPScanner() *common.Scanner {
	return icmpInstance
}
