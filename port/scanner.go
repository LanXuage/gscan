package port

import (
	"gscan/common"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

var logger = common.GetLogger()

type PortScan struct {
	Stop chan struct{}
}

func New() *PortScan {
	p := &PortScan{
		Stop: make(chan struct{}),
	}

	return p
}

func (p *PortScan) Close() {
	<-p.Stop
}

func (p *PortScan) TCPScan(ipList []net.IP, scanPorts []layers.TCPPort, scanType uint8) *TCPScanner {
	return nil
}

func (p *PortScan) UDPScan(ipList []net.IP) *UDPScanner {
	udp := InitialUDPScanner()

	logger.Debug("Start Recv")
	go udp.Recv()

	logger.Debug("Start Scan")
	go udp.Scan()

	logger.Debug("Start Generate")
	go udp.GenerateTarget(ipList)

	// go udp.CheckIPList(ipList)

	time.Sleep(udp.Timeout)

	return udp
}
