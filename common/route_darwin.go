//go:build darwin
// +build darwin

package common

import (
	"bytes"
	"fmt"
	"net"
)

type Interface struct {
	Port       string
	DeviceName string
}

func GetGateways() []net.IP {
	// 做两次筛选
	// 第一次为关键字：IP address、Subnet mask、 Router
	// 第二次为mac地址：查询是否存在mac地址，通过匹配null关键字
	// 查询结果模板：
	// DHCP Configuration
	// IP address: 192.168.2.137
	// Subnet mask: 255.255.255.0
	// Router: 192.168.2.1
	// Client ID:
	// IPv6: Automatic
	// IPv6 IP address: none
	// IPv6 Router: none
	// Wi-Fi ID: bc:d0:74:2c:5b:11

	ifs := GetInterfaces()
	gateways := []net.IP{}
	baseCommand := "networksetup -getinfo \"%s\""

	for _, iface := range ifs {
		if out := Exec(fmt.Sprintf(baseCommand, iface.Port)); out != nil {

			// 第一次关键字过滤
			if !bytes.Contains(out, []byte("IP address")) ||
				!bytes.Contains(out, []byte("Subnet mask")) ||
				!bytes.Contains(out, []byte("Router")) {
				continue
			}

			infoByte := bytes.Split(out, []byte{0x0a})[1:] // 通过换行符进行分割

			// 第二次mac地址值校验
			macAddr := bytes.Split(infoByte[len(infoByte)-2], []byte(": ")) //
			// logger.Sugar().Debug(string(macAddr[1]))

			if bytes.Contains(macAddr[1], []byte("null")) { // 网卡物理地址是否为null
				continue
			}

			// 获取网卡其他信息
			gateway := string(bytes.Split(infoByte[2], []byte(": "))[1])
			// logger.Debug(gateway)
			gateways = append(gateways, net.ParseIP(gateway).To4())
		}
	}
	logger.Sugar().Debug(gateways)
	return gateways
}

func GetInterfaces() []Interface {
	out := Exec("networksetup -listnetworkserviceorder | grep \"Hardware Port\"")
	res := bytes.Split(out, []byte("\n"))

	ifs := []Interface{}
	for _, r := range res {
		r2 := bytes.Split(r, []byte(", "))

		if len(r2) == 2 {
			r3 := bytes.Split(r2[0], []byte(": ")) // 取网卡端口

			r4 := bytes.Split(r2[1], []byte(": ")) // 取网卡设备名
			r5 := bytes.Replace(r4[1], []byte(")"), []byte(""), -1)

			ifs = append(ifs, Interface{
				Port:       string(r3[1]),
				DeviceName: string(r5),
			})
		}

	}
	// logger.Sugar().Debug(ifs)
	return ifs
}
