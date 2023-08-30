package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

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

func Exec(command string) []byte {
	cmd := exec.Command("sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Exec command failed", zap.String("cmd", command), zap.Error(err))
	}
	return out
}

func Bytes2Runes(b []byte) []rune {
	r := []rune{}
	for _, i := range b {
		r = append(r, rune(i))
	}
	return r
}

func Runes2Bytes(r []rune) []byte {
	b := []byte{}
	for _, i := range r {
		b = append(b, byte(i))
	}
	return b
}

func WaitTimeout(timeoutCh chan struct{}, timeout time.Duration) {
	defer close(timeoutCh)
	time.Sleep(timeout)
}

func GetDefaultPorts() *[]layers.TCPPort {
	return &[]layers.TCPPort{20, 21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 161, 443, 445, 901, 991, 1025, 1026, 1029, 1080, 1099, 1433, 1521, 1526, 1723, 1863, 1900, 2179, 2483, 2484, 3306, 3389, 5000, 5040, 5091, 5357, 5432, 5800, 5900, 6379, 7001, 7680, 8000, 8008, 8009, 8080, 8090, 8443, 8888, 9000, 9001, 9200, 10808, 10809, 27017}
}

func Close() {
	defer GEOIP2_DB.Close()
}
