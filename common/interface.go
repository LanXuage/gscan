package common

import (
	"net"
	"net/netip"

	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

// @De
type GSInterface struct {
	Name    string           // 接口名称
	Gateway net.IP           // 接口网关IP
	Mask    uint32           // 接口掩码
	HWAddr  net.HardwareAddr // 接口物理地址
	IP      net.IP           // 接口IP
	Handle  *pcap.Handle     // 接口pcap句柄
}

type GSIface struct {
	Name    string           // 接口名称
	Gateway netip.Addr       // 接口网关IP
	Mask    netip.Prefix     // 接口掩码
	HWAddr  net.HardwareAddr // 接口物理地址
	IP      netip.Addr       // 接口IP
	Handle  *pcap.Handle     // 接口pcap句柄
}

var localhost, _ = netip.ParseAddr("127.0.0.1")

func getActiveInterfaces() *[]GSInterface {
	gsInterfaces := make([]GSInterface, 0)
	gateways := GetGateways()
	devs, err := pcap.FindAllDevs()
	if err != nil {
		logger.Error("FindAllDevs failed", zap.Error(err))
	}
	ifs, err := net.Interfaces()
	if err != nil {
		logger.Error("Net Interfaces failed", zap.Error(err))
	}
	for _, gateway := range gateways {
		for _, dev := range devs {
			if dev.Addresses == nil {
				continue
			}
			for _, addr := range dev.Addresses {
				if addr.IP == nil {
					continue
				}
				maskUint32 := IPMask2Uint32(addr.Netmask)
				if !IsSameLAN(addr.IP, gateway, maskUint32) {
					continue
				}
				for _, i := range ifs {
					if i.Name != dev.Name {
						continue
					}
					gsInterface := GSInterface{
						Name:    i.Name,
						Gateway: gateway,
						Mask:    maskUint32,
						Handle:  GetHandle(i.Name),
						HWAddr:  i.HardwareAddr,
						IP:      addr.IP,
					}
					logger.Debug("Get gs iface", zap.Any("gsIface", gsInterface))
					gsInterfaces = append(gsInterfaces, gsInterface)
				}
			}
		}
	}
	return &gsInterfaces
}

func getActiveIfaces() *[]GSIface {
	gsInterfaces := make([]GSIface, 0)
	gateways := Gways()
	devs, err := pcap.FindAllDevs()
	if err != nil {
		logger.Error("FindAllDevs failed", zap.Error(err))
	}
	ifs, err := net.Interfaces()
	if err != nil {
		logger.Error("Net Interfaces failed", zap.Error(err))
	}
	for _, gateway := range gateways {
		for _, dev := range devs {
			if dev.Addresses == nil {
				continue
			}
			for _, addr := range dev.Addresses {
				if addr.IP == nil {
					continue
				}
				ones, _ := addr.Netmask.Size()
				ip, ok := netip.AddrFromSlice(addr.IP)
				if !ok || ip == localhost {
					continue
				}
				if (ip.Is4() && !gateway.Is4()) || (ip.Is6() && !gateway.Is6()) {
					continue
				}
				ipPrefix, err := ip.Prefix(ones)
				if err != nil {
					continue
				}
				if err != nil || !ipPrefix.Contains(gateway) {
					continue
				}
				for _, i := range ifs {
					if i.Name != dev.Name {
						continue
					}
					gsInterface := GSIface{
						Name:    i.Name,
						Gateway: gateway,
						Mask:    ipPrefix,
						Handle:  GetHandle(i.Name),
						HWAddr:  i.HardwareAddr,
						IP:      ip,
					}
					logger.Debug("Get gs iface", zap.Any("gsIface", gsInterface))
					gsInterfaces = append(gsInterfaces, gsInterface)
				}

			}
		}
	}
	return &gsInterfaces
}

var gsInterface = getActiveInterfaces()

// Deprecated: Use common.GetActiveIfaces instead.
func GetActiveInterfaces() *[]GSInterface {
	return gsInterface
}

func GetInterfaceBySrcMac(srcMac net.HardwareAddr) *GSInterface {
	for _, iface := range *getActiveInterfaces() {
		if iface.HWAddr.String() == srcMac.String() {
			return &iface
		}
	}
	return nil
}

func GetIfaceBySrcMac(srcMac net.HardwareAddr) *GSIface {
	for _, iface := range *getActiveIfaces() {
		if iface.HWAddr.String() == srcMac.String() {
			return &iface
		}
	}
	return nil
}

var gsIfaces = getActiveIfaces()

func GetActiveIfaces() *[]GSIface {
	return gsIfaces
}
