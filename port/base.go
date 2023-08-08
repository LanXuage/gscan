package port

import (
	"net"

	"github.com/LanXuage/gscan/arp"
	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/icmp"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var arpInstance = arp.GetARPScanner()
var receiver = common.GetReceiver()

var logger = common.GetLogger()

const (
	TCP_REGISTER_NAME       = "TCP"
	UDPREGISTER_NAME        = "UDP"
	DEFAULT_PORTS     uint8 = 0
	ALL_PORTS         uint8 = 1
	CUSTOM_PORTS      uint8 = 2
)

type TCPResult struct {
	icmp.ICMPScanResult
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

func GetTCPScanner() *common.Scanner {
	return tcpInstance
}
