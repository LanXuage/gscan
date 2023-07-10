package port

import (
	"net"
	"net/netip"

	"github.com/LanXuage/gscan/arp"
	"github.com/LanXuage/gscan/common"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var arpInstance = arp.GetARPScanner()
var receiver = common.GetReceiver()

const (
	TCP_REGISTER_NAME = "TCP"
	UDPREGISTER_NAME  = "UDP"
	DEFAULT_PORTS     = 0
	ALL_PORTS         = 1
	CUSTOM_PORTS      = 2
	MAX_CHANNEL_SIZE  = 256
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

type RandArea [2]int

var tcpInstance = newTCPScanner()

func GetTCPScanner() *TCPScanner {
	return tcpInstance
}
