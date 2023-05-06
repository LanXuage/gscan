package port

import (
	"gscan/common"
	"gscan/common/ports"
	"math/rand"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

type TCPScanner struct {
	TargetCh     chan *TCPTarget
	ResultCh     chan *TCPResult
	Timeout      time.Duration
	SrcPort      layers.TCPPort
	OpenPorts    cmap.ConcurrentMap[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, bool]]
	Opts         gopacket.SerializeOptions
	UseFullTCP   bool
	PortScanType int8
	Ports        []layers.TCPPort
}

func (t *TCPScanner) Save(sip []byte, sport layers.TCPPort) {

}

func (t *TCPScanner) RecvTCP(packet gopacket.Packet) interface{} {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}
	eth := ethLayer.(*layers.Ethernet)
	if eth == nil {
		return nil
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip := ipLayer.(*layers.IPv4)
	if ip == nil {
		return nil
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	if tcp == nil || tcp.DstPort != t.SrcPort {
		return nil
	}
	if tcp.RST && tcp.ACK {
		return nil
	}
	if srcIface := common.GetIfaceBySrcMac(eth.SrcMAC); srcIface != nil && tcp.SrcPort == t.SrcPort {
		return nil
	}
	if tcp.SYN && tcp.ACK && t.UseFullTCP {
		iface := common.GetInterfaceBySrcMac(eth.DstMAC)
		if iface != nil {
			iface := common.GetInterfaceBySrcMac(eth.DstMAC)
			t.TargetCh <- &TCPTarget{
				SrcIP:    ip.DstIP,
				DstIP:    ip.SrcIP,
				DstPorts: &[]layers.TCPPort{tcp.SrcPort},
				SrcMac:   eth.DstMAC,
				DstMac:   eth.SrcMAC,
				Ack:      tcp.Seq + 1,
				Handle:   iface.Handle,
			}
			return nil
		}
	}
	srcIP, _ := netip.AddrFromSlice(ip.SrcIP)
	if _, ok := t.OpenPorts.Get(srcIP); !ok {
		portSet := cmap.NewWithCustomShardingFunction[layers.TCPPort, bool](func(key layers.TCPPort) uint32 { return uint32(key) })
		t.OpenPorts.Set(srcIP, portSet)
	}
	if res, ok := t.OpenPorts.Get(srcIP); ok {
		if _, ok := res.Get(tcp.SrcPort); ok {
			return nil
		}
		res.Set(tcp.SrcPort, true)
	}
	return &TCPResult{
		IP:   srcIP,
		Port: tcp.SrcPort,
	}
}

func (t *TCPScanner) Recv() {
	defer close(t.ResultCh)
	for r := range receiver.Register(TCP_REGISTER_NAME, t.RecvTCP) {
		if result, ok := r.(*TCPResult); ok {
			t.ResultCh <- result
		}
	}
}

func (t *TCPScanner) SendSYNACK(target *TCPTarget) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       target.SrcMac,
		DstMAC:       target.DstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		Id:       uint16(rand.Intn(65535)),
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    target.SrcIP,
		DstIP:    target.DstIP,
		Flags:    layers.IPv4DontFragment,
	}
	for _, dstPort := range *target.DstPorts {
		var tcpLayer *layers.TCP
		if target.Ack == 0 {
			tcpLayer = &layers.TCP{
				SrcPort: t.SrcPort,
				DstPort: dstPort,
				Seq:     100,
				SYN:     true,
				Window:  64240,
				Options: []layers.TCPOption{
					{
						OptionType:   layers.TCPOptionKindMSS,
						OptionLength: 4,
						OptionData:   []byte{5, 0xb4},
					},
					{
						OptionType: layers.TCPOptionKindNop,
					},
					{
						OptionType: layers.TCPOptionKindNop,
					},
					{
						OptionType:   layers.TCPOptionKindSACKPermitted,
						OptionLength: 2,
					},
					{
						OptionType: layers.TCPOptionKindNop,
					},
					{
						OptionType:   layers.TCPOptionKindWindowScale,
						OptionLength: 3,
						OptionData:   []byte{7},
					},
				},
			}
		} else {
			tcpLayer = &layers.TCP{
				SrcPort: t.SrcPort,
				DstPort: dstPort,
				Seq:     101,
				Ack:     target.Ack,
				ACK:     true,
				Window:  502,
				Padding: []byte{0},
			}

		}
		if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
			logger.Error("SetNetwordLayerForChecksum Failed", zap.Error(err))
		}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, t.Opts, ethLayer, ipLayer, tcpLayer); err != nil {
			logger.Error("SerializeLayers Failed", zap.Error(err))
		}
		data := buffer.Bytes()
		if err := target.Handle.WritePacketData(data); err != nil {
			logger.Error("WritePacketData Failed", zap.Error(err))
		}
	}
}

func (t *TCPScanner) Scan() {
	for target := range t.TargetCh {
		t.SendSYNACK(target)
	}
}

func (t *TCPScanner) Close() {
	receiver.Unregister(TCP_REGISTER_NAME)
	close(t.TargetCh)
	close(t.ResultCh)
}

func (t *TCPScanner) ScanLocalNet() chan struct{} {
	timeoutCh := make(chan struct{})
	go t.generateLocalNetTarget(timeoutCh)
	return timeoutCh
}

func (t *TCPScanner) generateLocalNetTarget(timeoutCh chan struct{}) {
	for _, iface := range *common.GetActiveIfaces() {
		t.generateTargetByPrefix(iface.Mask, iface)
	}
	time.Sleep(t.Timeout)
	close(timeoutCh)
}

func (t *TCPScanner) generateTarget(ip netip.Addr, iface common.GSIface) {
	dstMac, _ := arpInstance.AHMap.Get(iface.Gateway)
	if ip == iface.IP {
		dstMac = iface.HWAddr
	}
	dstPorts := ports.GetDefaultPorts()
	if t.PortScanType == ALL_PORTS {
		dstPorts = &[]layers.TCPPort{}
		for i := 1; i < 65536; i++ {
			*dstPorts = append(*dstPorts, layers.TCPPort(i))
		}
	} else if t.PortScanType == CUSTOM_PORTS {
		dstPorts = &t.Ports
	}
	t.TargetCh <- &TCPTarget{
		SrcMac:   iface.HWAddr,
		DstMac:   dstMac,
		SrcIP:    iface.IP.AsSlice(),
		DstIP:    ip.AsSlice(),
		Ack:      0,
		DstPorts: dstPorts,
		Handle:   iface.Handle,
	}
}

func (t *TCPScanner) generateTargetByPrefix(prefix netip.Prefix, iface common.GSIface) {
	for i := 0; i < 2; i++ {
		nIp := prefix.Addr()
		for {
			if (nIp.Is4() && nIp.AsSlice()[3] != 0) || (nIp.Is6() && nIp.AsSlice()[15] != 0) {
				if !nIp.IsValid() || !prefix.Contains(nIp) || !iface.Mask.Contains(nIp) {
					break
				} else {
					t.generateTarget(nIp, iface)
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

func (t *TCPScanner) goScanMany(targetIPs []netip.Addr, timeoutCh chan struct{}) {
	for _, targetIP := range targetIPs {
		for _, iface := range *common.GetActiveIfaces() {
			t.generateTarget(targetIP, iface)
		}
	}
	time.Sleep(t.Timeout)
	close(timeoutCh)
}

func (t *TCPScanner) ScanMany(targetIPs []netip.Addr) chan struct{} {
	timeoutCh := make(chan struct{})
	go t.goScanMany(targetIPs, timeoutCh)
	return timeoutCh
}

func (t *TCPScanner) goScanPrefix(prefix netip.Prefix, timetouCh chan struct{}) {
	for _, iface := range *arpInstance.Ifas {
		if iface.Mask.Contains(prefix.Addr()) {
			t.generateTargetByPrefix(prefix, iface)
		}
	}
	time.Sleep(t.Timeout)
	close(timetouCh)
}

func (t *TCPScanner) ScanPrefix(prefix netip.Prefix) chan struct{} {
	timeoutCh := make(chan struct{})
	go t.goScanPrefix(prefix, timeoutCh)
	return timeoutCh
}

func newTCPScanner() *TCPScanner {
	rand.Seed(time.Now().Unix())
	t := &TCPScanner{
		TargetCh:     make(chan *TCPTarget, 10),
		ResultCh:     make(chan *TCPResult, 10),
		Timeout:      3 * time.Second,
		SrcPort:      layers.TCPPort(30768 + rand.Intn(34767)),
		OpenPorts:    cmap.NewWithCustomShardingFunction[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, bool]](common.Fnv32),
		Opts:         gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		UseFullTCP:   false,
		PortScanType: DEFAULT_PORTS,
		Ports:        []layers.TCPPort{},
	}
	go t.Recv()
	go t.Scan()
	return t
}
