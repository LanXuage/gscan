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
	Stop      chan struct{}        // 发包结束的信号
	TargetCh  chan *ICMPTarget     // 暂存单个所需扫描的IP
	ResultCh  chan *ICMPScanResult // 暂存单个IP扫描结果
	TResultCh chan *ICMPTTLResult  // TTL Channel
	Results   ICMPResultMap        // 存放本次扫描结果
	TResults  []ICMPTTLResult      // 存放TTL扫描结果
	IPList    []netip.Addr         // 存放本次所需扫描的IP
	Timeout   time.Duration        // 默认超时时间
	TTL       uint8                // 默认Time To Live
}

type ICMPTarget struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  netip.Addr       // 发包的源协议IP
	DstIP  netip.Addr       // 目的IP
	DstMac net.HardwareAddr // 目的Mac
	Handle *pcap.Handle     // 发包的具体句柄地址
}

type ICMPScanResult struct {
	IP       netip.Addr
	IsActive bool // 是否存活
}

type ICMPResultMap *cmap.ConcurrentMap[string, bool]

type ICMPTTLResult struct {
	IP        netip.Addr
	ReplyTime [3]float32
}

func NewICMPScanner() *ICMPScanner {
	_rMap := cmap.New[bool]()
	rMap := ICMPResultMap(&_rMap)

	icmpScanner := &ICMPScanner{
		Stop:     make(chan struct{}),
		TargetCh: make(chan *ICMPTarget, constant.CHANNEL_SIZE),
		ResultCh: make(chan *ICMPScanResult, constant.CHANNEL_SIZE),
		Results:  rMap,
		IPList:   []netip.Addr{},
		Timeout:  time.Second * 3,
		TTL:      64,
	}

	// go common.SetBPF("icmp")
	go icmpScanner.Recv()
	go icmpScanner.Scan()

	return icmpScanner
}

func (icmpScanner *ICMPScanner) Close() {
	common.GetReceiver().Unregister(constant.ICMPREGISTER_NAME)
	common.GetReceiver().Unregister("ttl")

	close(icmpScanner.Stop)
	close(icmpScanner.ResultCh)
	close(icmpScanner.TargetCh)

	// common.RemoveBPF()
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
			TTL:      icmpScanner.TTL,
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
		icmpScanner.SendICMP(target)
	}
}

func (icmpScanner *ICMPScanner) ScanList(ipList []netip.Addr) chan struct{} {
	timeoutCh := make(chan struct{})
	go icmpScanner.goGenerateTargetByIPList(ipList, timeoutCh)
	return timeoutCh
}

func (icmpScanner *ICMPScanner) ScanOne(ip netip.Addr) {
	for _, iface := range *arpInstance.Ifas {
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
}

func (icmpScanner *ICMPScanner) goGenerateTargetByIPList(ipList []netip.Addr, timeoutCh chan struct{}) {
	if arpInstance.Ifas == nil {
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
					SrcIP:  iface.IP,
					DstIP:  ip,
					SrcMac: iface.HWAddr,
					Handle: iface.Handle,
					DstMac: dstMac,
				}
			}
		}
	}

	time.Sleep(icmpScanner.Timeout)
	close(timeoutCh)
}

// CIDR Scanner
func (icmpScanner *ICMPScanner) ScanListByPrefix(prefix netip.Prefix) chan struct{} {
	timeoutCh := make(chan struct{})
	go icmpScanner.goGenerateTargetPrefix(prefix, timeoutCh)
	return timeoutCh
}

func (icmpScanner *ICMPScanner) goGenerateTargetPrefix(prefix netip.Prefix, timeoutCh chan struct{}) {
	for _, iface := range *arpInstance.Ifas {
		icmpScanner.generateTargetByPrefix(prefix, iface)
	}

	time.Sleep(icmpScanner.Timeout)
	close(timeoutCh)
}

func (icmpScanner *ICMPScanner) generateTargetByPrefix(prefix netip.Prefix, iface common.GSIface) {
	nIP := prefix.Addr()
	for {
		if nIP.IsValid() && prefix.Contains(nIP) {
			if dstMac, ok := arpInstance.AHMap.Get(iface.Gateway); ok {
				icmpScanner.TargetCh <- &ICMPTarget{
					SrcIP:  iface.IP,
					DstIP:  nIP,
					SrcMac: iface.HWAddr,
					Handle: iface.Handle,
					DstMac: dstMac,
				}
			}
			icmpScanner.IPList = append(icmpScanner.IPList, nIP)
			nIP = nIP.Next()
		} else {
			break
		}
	}
}

func (icmpScanner *ICMPScanner) GetTTL(ip netip.Addr) {

}

func (icmpScanner *ICMPScanner) SendTTL() {

}

// 接收TTL
func (icmpScanner *ICMPScanner) RecvTTL() {
	for r := range common.GetReceiver().Register("ttl", icmpScanner.RecvICMP) {
		if result, ok := r.(ICMPTTLResult); ok {
			icmpScanner.TResultCh <- &result
		}
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

		// 正常ICMP响应包
		if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply &&
			icmp.TypeCode.Code() == layers.ICMPv4CodeNet {
			ip := common.PacketToIPv4(packet)
			if ip != nil {
				if _, ok := (*icmpScanner.Results).Get(ip.To4().String()); !ok {

					(*icmpScanner.Results).Set(ip.To4().String(), true)
					_ip, _ := netip.AddrFromSlice(ip)

					return ICMPScanResult{
						IP:       _ip,
						IsActive: true,
					}
				}
			}
		}

		// TTL ICMP响应包
		if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded &&
			icmp.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
			ip := common.PacketToIPv4(packet)
			if ip != nil {
				_ip, _ := netip.AddrFromSlice(ip)

				return ICMPTTLResult{
					IP: _ip,
				}
			}
		}
	}
	return nil
}

// 校验IPLIST
func (icmpScanner *ICMPScanner) CheckIPList(timeoutCh chan struct{}) {

	time.Sleep(icmpScanner.Timeout)
	for _, ip := range icmpScanner.IPList {
		if _, ok := (*icmpScanner.Results).Get(ip.String()); !ok {
			// 该IP未进扫描结果，此时发包结束，并且经过一定时间的延时，未收到返回包，说明并未Ping通
			icmpScanner.ResultCh <- &ICMPScanResult{
				IP:       ip,
				IsActive: false,
			}
			(*icmpScanner.Results).Set(ip.String(), false)
		}
	}
	close(timeoutCh)
}

var icmpInstance = NewICMPScanner()

func GetICMPScanner() *ICMPScanner {
	return icmpInstance
}
