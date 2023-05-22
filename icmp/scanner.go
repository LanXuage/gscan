package icmp

import (
	"fmt"
	"log"
	"math/rand"
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
	Choice    int                  // 选择常规Ping或TTL，默认为常规Ping，值为1，选择TTL则设置为2
	TmpTime   time.Time            // TTL时需要用到的时间
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
	IP netip.Addr
}

type ICMPTTLResultMap *cmap.ConcurrentMap[string, []time.Duration]

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
		Choice:   1,
	}

	return icmpScanner
}

func (icmpScanner *ICMPScanner) Init() {
	go icmpScanner.Recv()
	go icmpScanner.Scan()
}

func (icmpScanner *ICMPScanner) Close() {
	switch icmpScanner.Choice {
	case 1:
		common.GetReceiver().Unregister(constant.ICMPREGISTER_NAME)
	case 2:
		common.GetReceiver().Unregister(constant.TTLREGISTER_NAME)
	}

	close(icmpScanner.Stop)
	close(icmpScanner.ResultCh)
	close(icmpScanner.TargetCh)

	// common.RemoveBPF()
}

// ICMP发包
func (icmpScanner *ICMPScanner) SendICMP(target *ICMPTarget) {
	payload := []byte("") // 特征
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

// Deprecated: use SendTTLbyUDP instead.
func (icmpScanner *ICMPScanner) SendTTLbyICMP(target *ICMPTarget) {
	payload := []byte("") // 特征
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
		}

		icmpLayer := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, layers.ICMPv4CodeNet),
			Id:       constant.ICMPId,
			Seq:      constant.ICMPSeq,
		}

		var ttl uint8 = 1
		for ; ttl < icmpScanner.TTL; ttl++ {
			ipLayer.TTL = ttl

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

			err = target.Handle.WritePacketData(buffer.Bytes())
			if err != nil {
				log.Fatal(err)
			}
			time.Sleep(time.Second * 1)
		}

	} else {
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}
}

// TTL探测 UDP 发包
func (icmpScanner *ICMPScanner) SendTTLbyUDP(target *ICMPTarget) {
	udpBuffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	// 构建以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC: target.SrcMac,
		DstMAC: target.DstMac,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		SrcIP:    target.SrcIP.AsSlice(),
		DstIP:    target.DstIP.AsSlice(),
		Protocol: layers.IPProtocolUDP,
	}

	if target.SrcIP.Is4() {
		ethLayer.EthernetType = layers.EthernetTypeIPv4
		var ttl uint8 = 1
		for ; ttl <= icmpScanner.TTL; ttl++ {
			fmt.Printf("TTL: %d\n", ttl)
			for i := 0; i < 3; i++ {
				ipLayer.TTL = ttl

				udpLayer := &layers.UDP{
					SrcPort: layers.UDPPort(30768 + rand.Intn(34767)),
					DstPort: layers.UDPPort(30768 + rand.Intn(34767)),
				}

				udpLayer.SetNetworkLayerForChecksum(ipLayer)

				err := gopacket.SerializeLayers(
					udpBuffer,
					opts,
					ethLayer,
					ipLayer,
					udpLayer,
				)
				if err != nil {
					logger.Error("SerializeLayers Failed", zap.Error(err))
				}

				err = target.Handle.WritePacketData(udpBuffer.Bytes())
				if err != nil {
					logger.Error("WritePacketData Failed", zap.Error(err))
				}

			}
			time.Sleep(time.Millisecond * 400)
		}

	} else {
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}
}

func (icmpScanner *ICMPScanner) Scan() {
	switch icmpScanner.Choice {
	case 1:
		for target := range icmpScanner.TargetCh {
			icmpScanner.SendICMP(target)
		}
	case 2:
		for target := range icmpScanner.TargetCh {
			icmpScanner.SendTTLbyUDP(target)
		}
	}
}

func (icmpScanner *ICMPScanner) ScanList(ipList []netip.Addr) chan struct{} {
	timeoutCh := make(chan struct{})
	go icmpScanner.goGenerateTargetByIPList(ipList, timeoutCh)
	return timeoutCh
}

func (icmpScanner *ICMPScanner) ScanOne(ip netip.Addr) chan struct{} {
	timeoutCh := make(chan struct{})
	go icmpScanner.goGenerateOne(ip, timeoutCh)
	return timeoutCh
}

func (icmpScanner *ICMPScanner) goGenerateOne(ip netip.Addr, timeoutCh chan struct{}) {
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

	time.Sleep(icmpScanner.Timeout)
	close(timeoutCh)
}

func (icmpScanner *ICMPScanner) goGenerateTargetByIPList(ipList []netip.Addr, timeoutCh chan struct{}) {
	if arpInstance.Ifas == nil {
		logger.Fatal("Get Ifaces Failed")
		return
	}

	if len(ipList) == 0 {
		logger.Fatal("ipList is NULL")
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

// 接收协程
func (icmpScanner *ICMPScanner) Recv() {
	switch icmpScanner.Choice {
	case 1:
		for r := range common.GetReceiver().Register(constant.ICMPREGISTER_NAME, icmpScanner.RecvICMP) {
			if result, ok := r.(ICMPScanResult); ok {
				icmpScanner.ResultCh <- &result
			}
		}
	case 2:
		for r := range common.GetReceiver().Register(constant.TTLREGISTER_NAME, icmpScanner.RecvICMP) {
			if result, ok := r.(ICMPTTLResult); ok {
				fmt.Println(result.IP)
				icmpScanner.TResultCh <- &result
			}
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

	// 常规PING响应包
	if icmp.Id == constant.ICMPId &&
		icmp.Seq == constant.ICMPSeq {
		// 正常PING ICMP响应包
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
	}

	// TTL 响应包
	if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded &&
		icmp.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
		ip := common.PacketToIPv4(packet)
		if ip != nil {
			_ip, _ := netip.AddrFromSlice(ip)
			tmp := ICMPTTLResult{
				IP: _ip,
			}
			fmt.Println(tmp)
			return tmp
		}
	}

	if icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable &&
		icmp.TypeCode.Code() == layers.ICMPv4CodePort {
		ip := common.PacketToIPv4(packet)
		if ip != nil {
			fmt.Printf("Arrive The Destination: %s\n", ip)
			return ICMPTTLResult{}
		}
	}
	return nil
}

var icmpInstance = NewICMPScanner()

func GetICMPScanner() *ICMPScanner {
	return icmpInstance
}
