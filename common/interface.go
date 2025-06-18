package common

import (
	"net"
	"net/netip"
	"strings"

	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

type GSIface struct {
	Name     string           // 接口名称
	Gateway  netip.Addr       // 接口网关IP
	Mask     netip.Prefix     // 接口掩码
	HWAddr   net.HardwareAddr // 接口物理地址
	GWHWAddr net.HardwareAddr // 接口网关物理地址
	IP       netip.Addr       // 接口IP
	Handle   *pcap.Handle     // 接口pcap句柄
}

var localhost netip.Addr

func init() {
	localhost, _ = netip.ParseAddr("127.0.0.1")
}

func getPcapDevs() []pcap.Interface {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		if err.Error() == "couldn't load wpcap.dll" {
			logger.Panic("Please install Npcap first, visit https://npcap.com/ to download. ")
		} else {
			logger.Error("FindAllDevs failed", zap.Error(err))
		}
	}
	return devs
}

func getActiveIfaces() *[]GSIface {
	gsInterfaces := make([]GSIface, 0)
	gateways := Gways()
	ifs, err := net.Interfaces()
	if err != nil {
		logger.Error("Net Interfaces failed", zap.Error(err))
	}
	for _, gateway := range gateways {
		for _, dev := range getPcapDevs() {
			if dev.Addresses == nil {
				continue
			}
			for _, addr := range dev.Addresses {
				if addr.IP == nil {
					continue
				}
				ones, _ := addr.Netmask.Size()
				ip, ok := netip.AddrFromSlice(addr.IP)
				if !ok || ip == localhost || (ip.Is4() && !gateway.Is4()) || (ip.Is6() && !gateway.Is6()) {
					continue
				}
				ipPrefix, err := ip.Prefix(ones)
				if err != nil || !ipPrefix.Contains(gateway) {
					continue
				}
				for _, i := range ifs {
					addrs, err := i.Addrs()
					if err != nil {
						continue
					}
					for _, iAddr := range addrs {
						if strings.Contains(iAddr.String(), ip.String()) {
							gsInterface := GSIface{
								Name:    dev.Name,
								Gateway: gateway,
								Mask:    ipPrefix,
								Handle:  GetHandle(dev.Name),
								HWAddr:  i.HardwareAddr,
								IP:      ip,
							}
							gsInterfaces = append(gsInterfaces, gsInterface)
							break
						}
					}
				}

			}
		}
	}
	return &gsInterfaces
}

func GetIfaceBySrcMac(srcMac net.HardwareAddr) *GSIface {
	for _, iface := range *getActiveIfaces() {
		if iface.HWAddr.String() == srcMac.String() {
			return &iface
		}
	}
	return nil
}

var gsIfaces *[]GSIface

func init() {
	localhost, _ = netip.ParseAddr("127.0.0.1")
	gsIfaces = getActiveIfaces()
}

func GetActiveIfaces() *[]GSIface {
	return gsIfaces
}
