package port

import (
	"math/rand"
	"net/netip"
	"time"

	"github.com/LanXuage/gscan/arp"
	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/icmp"

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
	PortScanType uint8
	Ports        []layers.TCPPort
	gCount       int64
	sCount       int64
	UseRandom    bool
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
		iface := common.GetIfaceBySrcMac(eth.DstMAC)
		if iface != nil {
			iface := common.GetIfaceBySrcMac(eth.DstMAC)
			t.addTarget(&TCPTarget{
				SrcIP:    ip.DstIP,
				DstIP:    ip.SrcIP,
				DstPorts: &[]layers.TCPPort{tcp.SrcPort},
				SrcMac:   eth.DstMAC,
				DstMac:   eth.SrcMAC,
				Ack:      tcp.Seq + 1,
				Handle:   iface.Handle,
			}, true)
			return nil
		}
	}
	srcIP, _ := netip.AddrFromSlice(ip.SrcIP)
	t.OpenPorts.SetIfAbsent(srcIP, cmap.NewWithCustomShardingFunction[layers.TCPPort, bool](func(key layers.TCPPort) uint32 { return uint32(key) }))
	if res, ok := t.OpenPorts.Get(srcIP); ok {
		if !res.SetIfAbsent(tcp.SrcPort, true) {
			return nil
		}
	}
	return &TCPResult{
		ICMPScanResult: icmp.ICMPScanResult{
			ARPScanResult: arp.ARPScanResult{
				IP: srcIP,
			},
			IsActive: true,
		},
		Port: tcp.SrcPort,
	}
}

func (t *TCPScanner) Recv() {
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
	if t.UseRandom {
		dstPortsCount := len(*target.DstPorts)
		chLen := dstPortsCount / 8
		if chLen < 10 {
			chLen = 10
		}
		randAreaCh := make(chan RandArea, chLen)
		randAreaCh <- [2]int{0, dstPortsCount}
		for randArea := range randAreaCh {
			randIndex := randArea[0] + rand.Intn(randArea[1]-randArea[0])
			t.generateTCPLayerAndSend(target, (*target.DstPorts)[randIndex], ethLayer, ipLayer)
			dstPortsCount -= 1
			logger.Debug("sendSynAck", zap.Any("dstPortCount", dstPortsCount), zap.Any("targetChSize", len(t.TargetCh)), zap.Any("resultChSize", len(t.ResultCh)))
			if dstPortsCount == 0 {
				close(randAreaCh)
			}
			if randArea[1]-randIndex+1 > randIndex-randArea[0] {
				if randArea[0] < randIndex {
					randAreaCh <- [2]int{randArea[0], randIndex}
				}
				if randIndex+1 < randArea[1] {
					randAreaCh <- [2]int{randIndex + 1, randArea[1]}
				}
			} else {
				if randIndex+1 < randArea[1] {
					randAreaCh <- [2]int{randIndex + 1, randArea[1]}
				}
				if randArea[0] < randIndex {
					randAreaCh <- [2]int{randArea[0], randIndex}
				}
			}
		}
	} else {
		for _, dstPort := range *target.DstPorts {
			t.generateTCPLayerAndSend(target, dstPort, ethLayer, ipLayer)
		}
	}
}

func (t *TCPScanner) generateTCPLayerAndSend(target *TCPTarget, dstPort layers.TCPPort, ethLayer *layers.Ethernet, ipLayer *layers.IPv4) {
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
	time.Sleep(time.Microsecond * 1002)
}

func (t *TCPScanner) Scan() {
	for target := range t.TargetCh {
		if t.UseRandom && rand.Intn(3) == 0 {
			t.addTarget(target, false)
			continue
		}
		logger.Debug("Scan", zap.Any("targetChSize", len(t.TargetCh)), zap.Any("sCount", t.sCount))
		t.SendSYNACK(target)
		t.sCount += 1
	}
}

func (t *TCPScanner) Close() {
	defer close(t.TargetCh)
	defer close(t.ResultCh)
	receiver.Unregister(TCP_REGISTER_NAME)
}

func (t *TCPScanner) ScanLocalNet() chan struct{} {
	timeoutCh := make(chan struct{})
	go t.generateLocalNetTarget(timeoutCh)
	return timeoutCh
}

func (t *TCPScanner) generateLocalNetTarget(timeoutCh chan struct{}) {
	defer t.waitTimeout(timeoutCh)
	for _, iface := range *common.GetActiveIfaces() {
		t.generateTargetByPrefix(iface.Mask, iface)
	}
}

func (t *TCPScanner) waitTimeout(timeoutCh chan struct{}) {
	defer close(timeoutCh)
	for {
		time.Sleep(time.Millisecond * 1)
		logger.Debug("waitTimeout", zap.Any("gCount", t.gCount), zap.Any("sCount", t.sCount), zap.Any("targetChSize", len(t.TargetCh)))
		if t.gCount == t.sCount && len(t.TargetCh) == 0 {
			break
		}
	}
	time.Sleep(t.Timeout)
}

func (t *TCPScanner) generateTarget(ip netip.Addr, iface common.GSIface) {
	dstMac, _ := arpInstance.AHMap.Get(iface.Gateway)
	if ip == iface.IP {
		dstMac = iface.HWAddr
	}
	if len(dstMac) == 0 {
		return
	}
	dstPorts := common.GetDefaultPorts()
	if t.PortScanType == ALL_PORTS {
		dstPorts = &[]layers.TCPPort{}
		for i := 1; i < 65536; i++ {
			*dstPorts = append(*dstPorts, layers.TCPPort(i))
		}
	} else if t.PortScanType == CUSTOM_PORTS {
		dstPorts = &t.Ports
	}

	t.addTarget(&TCPTarget{
		SrcMac:   iface.HWAddr,
		DstMac:   dstMac,
		SrcIP:    iface.IP.AsSlice(),
		DstIP:    ip.AsSlice(),
		Ack:      0,
		DstPorts: dstPorts,
		Handle:   iface.Handle,
	}, true)
}

func (t *TCPScanner) addTarget(target *TCPTarget, addGCount bool) {
	for len(t.TargetCh) == MAX_CHANNEL_SIZE {
		logger.Debug("sleep", zap.Any("targetChSize", len(t.TargetCh)))
		time.Sleep(t.Timeout)
	}
	t.TargetCh <- target
	if addGCount {
		t.gCount += 1
	}
}

func (t *TCPScanner) generateTargetByPrefix(prefix netip.Prefix, iface common.GSIface) {
	for i := 0; i < 2; i++ {
		nIp := prefix.Addr()
		for {
			logger.Debug("generateTargetByPrefix", zap.Any("nIP", nIp))
			if (nIp.Is4() && nIp.AsSlice()[3] != 0 && nIp.AsSlice()[3] != 255) || (nIp.Is6() && nIp.AsSlice()[15] != 0 && (nIp.AsSlice()[14] != 255 || nIp.AsSlice()[15] != 255)) {
				if !nIp.IsValid() || !prefix.Contains(nIp) {
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
	defer t.waitTimeout(timeoutCh)
	for _, targetIP := range targetIPs {
		for _, iface := range *common.GetActiveIfaces() {
			t.generateTarget(targetIP, iface)
		}
	}
}

func (t *TCPScanner) ScanMany(targetIPs []netip.Addr) chan struct{} {
	timeoutCh := make(chan struct{})
	go t.goScanMany(targetIPs, timeoutCh)
	return timeoutCh
}

func (t *TCPScanner) goScanPrefix(prefix netip.Prefix, timeoutCh chan struct{}) {
	defer t.waitTimeout(timeoutCh)
	for _, iface := range *common.GetActiveIfaces() {
		t.generateTargetByPrefix(prefix, iface)
	}
}

func (t *TCPScanner) ScanPrefix(prefix netip.Prefix) chan struct{} {
	timeoutCh := make(chan struct{})
	go t.goScanPrefix(prefix, timeoutCh)
	return timeoutCh
}

func newTCPScanner() *TCPScanner {
	rand.Seed(time.Now().Unix())
	t := &TCPScanner{
		TargetCh:     make(chan *TCPTarget, MAX_CHANNEL_SIZE),
		ResultCh:     make(chan *TCPResult, MAX_CHANNEL_SIZE),
		Timeout:      3 * time.Second,
		SrcPort:      layers.TCPPort(30768 + rand.Intn(34767)),
		OpenPorts:    cmap.NewWithCustomShardingFunction[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, bool]](common.Fnv32),
		Opts:         gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		UseFullTCP:   false,
		PortScanType: DEFAULT_PORTS,
		Ports:        []layers.TCPPort{},
		UseRandom:    true,
	}
	go t.Recv()
	go t.Scan()
	return t
}
