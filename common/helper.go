package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

func GetOuiPrefix(mac net.HardwareAddr) (string, string) {
	ret1 := strings.ToUpper(strings.Replace(mac.String()[:8], ":", "", -1))
	ret2 := strings.ToUpper(strings.Replace(mac.String()[:13], ":", "", -1))
	return ret1, ret2
}

func Fnv32(key netip.Addr) uint32 {
	hash := uint32(2166136261)
	const prime32 = uint32(16777619)
	d := key.AsSlice()
	keyLength := len(d)
	for i := 0; i < keyLength; i++ {
		hash *= prime32
		hash ^= uint32(d[i])
	}
	return hash
}

func ToJSON(data interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("%+v", data)
	}
	var out bytes.Buffer
	err = json.Indent(&out, b, "", "    ")
	if err != nil {
		return fmt.Sprintf("%+v", data)
	}
	return out.String()
}

func IP2Uint32(ip net.IP) uint32 {
	var sum uint32
	sum += uint32(ip[0]) << 24
	sum += uint32(ip[1]) << 16
	sum += uint32(ip[2]) << 8
	return sum + uint32(ip[3])
}

func IPMask2Uint32(mask net.IPMask) uint32 {
	return IP2Uint32(net.IP(mask))
}

func Uint322IP(ipUint32 uint32) net.IP {
	return net.IPv4(byte((ipUint32>>24)&0xff), byte((ipUint32>>16)&0xff), byte((ipUint32>>8)&0xff), byte(ipUint32&0xff))
}

func IsSameLAN(ip net.IP, otherIp net.IP, mask uint32) bool {
	return IP2Uint32(ip)&mask == IP2Uint32(otherIp)&mask
}

func PacketToIPv4(packet gopacket.Packet) net.IP {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip != nil {
			return ip.SrcIP
		}
	}
	return net.IPv4zero
}

func GetHandle(deviceName string) *pcap.Handle {
	handle, err := pcap.OpenLive(deviceName, 65535, true, pcap.BlockForever)
	if err != nil {
		logger.Error("Get Handle failed", zap.String("deviceName", deviceName), zap.Error(err))
	}
	return handle
}

// Deprecated: use IPList2NetIPList instead
func _IPList2NetIPList(ipList []string) []net.IP {
	s := []net.IP{}
	for _, ip := range ipList {
		s = append(s, net.ParseIP(ip).To4())
	}
	return s
}

func IPList2NetIPList(ipList []string) []netip.Addr {
	ret := []netip.Addr{}
	for _, ip := range ipList {
		res, err := netip.ParseAddr(ip)
		if err != nil {
			logger.Error("IP Format Error!")
		}
		ret = append(ret, res)
	}
	return ret
}

// Deprecated: Use common.IsSameLAN instead.
func CheckIPisIPNet(ip net.IP, gateway net.IP, mask uint32) bool {

	ipArray := ip.To4()
	gatewayArray := gateway.To4()

	l := len(ipArray)
	if l != len(gatewayArray) {
		return false
	}
	for i := 0; i < l; i++ {
		if ipArray[i]&byte((mask>>(24-i*8))&0xff) != gatewayArray[i]&byte((mask>>(24-i*8))&0xff) {
			return false
		}
	}
	return true
}

func Exec(command string) []byte {
	cmd := exec.Command("sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Exec command failed", zap.String("cmd", command), zap.Error(err))
	}
	return out
}
