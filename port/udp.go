package port

import (
	"gscan/common"
	"gscan/common/constant"
	"gscan/common/ports"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

type UDPScanner struct {
	Stop     chan struct{}
	Results  []UDPResult
	ResultCh chan *UDPResult
	TargetCh chan *UDPTarget
	Timeout  time.Duration
}

type UDPTarget struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  layers.UDPPort
	DstPorts []layers.TCPPort
	SrcMac   net.HardwareAddr
	DstMac   net.HardwareAddr
	Handle   *pcap.Handle
}

type UDPResult struct {
	IP    net.IP
	Ports map[uint16]bool
}

func InitialUDPScanner() *UDPScanner {
	return &UDPScanner{
		Stop:     make(chan struct{}),
		Results:  []UDPResult{},
		ResultCh: make(chan *UDPResult, 10),
		TargetCh: make(chan *UDPTarget, 10),
		Timeout:  time.Second * 5,
	}
}

func (u *UDPScanner) GenerateTarget(ipList []net.IP) {
	defer close(u.TargetCh)

	ifaces := common.GetActiveInterfaces()
	if ifaces == nil || len(ipList) == 0 {
		return
	}

	for _, iface := range *ifaces {
		for _, ip := range ipList {
			ig, _ := netip.AddrFromSlice(iface.Gateway)
			igMac, _ := arpInstance.AHMap.Get(ig)
			tmp := &UDPTarget{
				SrcIP:    iface.IP,
				SrcPort:  layers.UDPPort(ports.DEFAULT_SOURCEPORT),
				DstIP:    ip,
				DstPorts: *ports.GetDefaultPorts(),
				SrcMac:   iface.HWAddr,
				DstMac:   igMac,
				Handle:   iface.Handle,
			}
			u.TargetCh <- tmp
		}
	}

}

func (u *UDPScanner) Scan() {
	defer close(u.Stop)
	for target := range u.TargetCh {
		u.SendUDP(target)
	}
}

func (u *UDPScanner) SendUDP(target *UDPTarget) {
	udpBuffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// 以太层
	ethLayer := &layers.Ethernet{
		SrcMAC:       target.SrcMac,
		DstMAC:       target.DstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IP层
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    target.SrcIP,
		DstIP:    target.DstIP,
		Protocol: layers.IPProtocolUDP,
	}

	for _, port := range target.DstPorts {
		udpLayer := &layers.UDP{
			SrcPort: target.SrcPort,
			DstPort: layers.UDPPort(port),
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

		// fmt.Println(udpBuffer)
		logger.Sugar().Infof("Send ip: %s, port: %d\n", target.DstIP, port)
	}

}

func (u *UDPScanner) Recv() {
	defer close(u.ResultCh)
	for r := range common.GetReceiver().Register(constant.UDPREGISTER_NAME, u.RecvUDP) {
		if result, ok := r.(*UDPResult); ok {
			u.ResultCh <- result
		}
	}
}

func (u *UDPScanner) RecvUDP(packet gopacket.Packet) interface{} {
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if udpLayer == nil {
		return nil
	}

	udp, _ := udpLayer.(*layers.UDP)
	if udp == nil {
		return nil
	}

	return nil
}

func (u *UDPScanner) CheckIPList(ipList []net.IP) {

}

func (u *UDPScanner) Close() {
	<-u.Stop
	common.GetReceiver().Unregister(constant.UDPREGISTER_NAME)
}
