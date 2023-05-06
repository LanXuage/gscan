package icmp

import (
	"gscan/arp"
	"gscan/common"
	"gscan/common/constant"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

var arpInstance = arp.GetARPScanner()
var logger = common.GetLogger()

type ICMPScanner struct {
	Stop     chan struct{}
	Results  ICMPResultMap
	TargetCh chan *ICMPTarget
	ResultCh chan *ICMPScanResult
	Timeout  time.Duration
}

type ICMPTarget struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  net.IP           // 发包的源协议IP
	DstIP  net.IP           // 目的IP
	DstMac net.HardwareAddr // 目的Mac
	Handle *pcap.Handle     // 发包的具体句柄地址
}

type ICMPScanResult struct {
	IP        net.IP
	IsActive  bool
	IsARPScan bool
	CostTTL   int16
}

type ICMPResultMap *cmap.ConcurrentMap[string, bool]

func New() *ICMPScanner {
	_rMap := cmap.New[bool]()
	rMap := ICMPResultMap(&_rMap)

	icmpScanner := &ICMPScanner{
		Stop:     make(chan struct{}),
		TargetCh: make(chan *ICMPTarget, 10),
		ResultCh: make(chan *ICMPScanResult, 15),
		Results:  rMap,
		Timeout:  time.Second * 4,
	}
	return icmpScanner
}

// ICMP发包
func (icmpScanner *ICMPScanner) SendICMP(target *ICMPTarget) {
	payload := []byte("Send ICMP by YuSec")
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	// 构建以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC:       target.SrcMac,
		DstMAC:       target.DstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// 构建IP数据包
	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    target.SrcIP,
		DstIP:    target.DstIP,
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
	}

	// 构建ICMP数据包
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
}

func (icmpScanner *ICMPScanner) GenerateTarget(ipList []net.IP) {
	defer close(icmpScanner.TargetCh)
	if arpInstance.Ifaces == nil {
		logger.Fatal("Get Ifaces Failed")
		return
	}

	if len(ipList) == 0 {
		logger.Fatal("IPList is NULL")
		return
	}

	for _, iface := range *arpInstance.Ifas {
		if dstMac, ok := arpInstance.AHMap.Get(iface.Gateway); ok {
			for _, ip := range ipList {
				icmpScanner.TargetCh <- &ICMPTarget{
					SrcIP:  iface.IP.AsSlice(),
					DstIP:  ip,
					SrcMac: iface.HWAddr,
					Handle: iface.Handle,
					DstMac: dstMac,
				}
			}
		}

	}
}

func (icmpScanner *ICMPScanner) Scan() {
	defer close(icmpScanner.Stop)
	for target := range icmpScanner.TargetCh {
		icmpScanner.SendICMP(target)
	}
}

func (icmpScanner *ICMPScanner) ScanList(ipList []net.IP) chan *ICMPScanResult {

	ipList = icmpScanner.filterIPList(ipList)

	logger.Sugar().Debug("ScanList:", ipList)

	logger.Debug("Start Generate...")
	go icmpScanner.GenerateTarget(ipList)

	logger.Debug("Start Listen...")
	go icmpScanner.Recv()

	logger.Debug("Start ICMP...")
	go icmpScanner.Scan()

	go icmpScanner.CheckIPList(ipList)

	return icmpScanner.ResultCh
}

func (icmpScanner *ICMPScanner) filterIPList(ipList []net.IP) []net.IP {
	for i := 0; i < len(ipList); i++ {
		ip, _ := netip.AddrFromSlice(ipList[i])
		if _, ok := arpInstance.AHMap.Get(ip); ok {
			(*icmpScanner.Results).Set(ipList[i].String(), true)
			icmpScanner.ResultCh <- &ICMPScanResult{
				IP:        ipList[i],
				IsActive:  true,
				IsARPScan: true,
			}
			ipList = append(ipList[:i], ipList[(i+1):]...) // 抹除ARP Scanner后的结果, 不计入生产者中
		}
	}

	return ipList

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
				(*icmpScanner.Results).Set(ip.To4().String(), true)
				return ICMPScanResult{
					IP:        ip.To4(),
					IsActive:  true,
					IsARPScan: false,
				}
			}
		}
	}
	return nil
}

// 校验IPLIST
func (icmpScanner *ICMPScanner) CheckIPList(ipList []net.IP) {
	<-icmpScanner.Stop
	for _, ip := range ipList {
		if _, ok := (*icmpScanner.Results).Get(ip.String()); ok {
			(*icmpScanner.Results).Set(ip.String(), false)
		}
	}
}

func (icmpScanner *ICMPScanner) Close() {
	common.GetReceiver().Unregister(constant.ICMPREGISTER_NAME)
}
