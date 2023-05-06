package port

import (
	"gscan/arp"
	"gscan/common"
	"net"
	"net/netip"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var arpInstance = arp.GetARPScanner()
var receiver = common.GetReceiver()

const (
	TCP_REGISTER_NAME = "TCP"
	DEFAULT_PORTS     = 0
	ALL_PORTS         = 1
	CUSTOM_PORTS      = 2
)

type TCPResult struct {
	IP   netip.Addr
	Port layers.TCPPort
}

type TCPTarget struct {
	SrcIP    []byte
	DstIP    []byte
	DstPorts *[]layers.TCPPort
	Ack      uint32
	SrcMac   net.HardwareAddr
	DstMac   net.HardwareAddr
	Handle   *pcap.Handle
}

var tcpInstance = newTCPScanner()

func GetTCPScanner() *TCPScanner {
	return tcpInstance
}
