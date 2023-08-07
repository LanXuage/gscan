package icmp

import (
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/LanXuage/gscan/arp"
	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/common/constant"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

var arpInstance = arp.GetARPScanner()
var logger = common.GetLogger()

type ICMPScanner struct {
	common.IScanner
	common.Scanner
	Results ICMPResultMap // 存放本次扫描结果
	IPList  []netip.Addr  // 存放本次所需扫描的IP
	Timeout time.Duration // 默认超时时间
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

func NewICMPScanner() *ICMPScanner {
	_rMap := cmap.New[bool]()
	rMap := ICMPResultMap(&_rMap)

	icmpScanner := &ICMPScanner{
		Results: rMap,
		IPList:  []netip.Addr{},
		Timeout: time.Second * 3,
	}

	go icmpScanner.Recv()
	go icmpScanner.Scan()

	return icmpScanner
}

func (icmpScanner *ICMPScanner) Close() {
	defer icmpScanner.Scanner.Close()
	common.GetReceiver().Unregister(constant.ICMPREGISTER_NAME)
}

func (icmpScanner *ICMPScanner) GenerateTarget(ip netip.Addr, iface common.GSIface) {
	logger.Info("bbbbbbbbbbbbbbbbbbbb")
	if dstMac, ok := arpInstance.AHMap.Get(iface.Gateway); ok {
		icmpScanner.TargetCh <- &ICMPTarget{
			SrcIP:  iface.IP,
			DstIP:  ip,
			SrcMac: iface.HWAddr,
			Handle: iface.Handle,
			DstMac: dstMac,
		}
	}
}

// ICMP发包
func (icmpScanner *ICMPScanner) SendICMP(target *ICMPTarget) {
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

func (icmpScanner *ICMPScanner) Scan() {
	for target := range icmpScanner.TargetCh {
		icmpScanner.SendICMP(target.(*ICMPTarget))
	}
}

// 接收协程
func (icmpScanner *ICMPScanner) Recv() {
	for r := range common.GetReceiver().Register(constant.ICMPREGISTER_NAME, icmpScanner.RecvICMP) {
		if result, ok := r.(ICMPScanResult); ok {
			icmpScanner.ResultCh <- &result
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

var icmpInstance = NewICMPScanner()

func GetICMPScanner() *ICMPScanner {
	return icmpInstance
}
