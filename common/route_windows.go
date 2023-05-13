//go:build windows

package common

import (
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

type RouteRow struct {
	ForwardDest      [4]byte //目标网络
	ForwardMask      [4]byte //掩码
	ForwardPolicy    uint32  //ForwardPolicy:0x0
	ForwardNextHop   [4]byte //网关
	ForwardIfIndex   uint32  // 网卡索引 id
	ForwardType      uint32  //3 本地接口  4 远端接口
	ForwardProto     uint32  //3静态路由 2本地接口 5EGP网关
	ForwardAge       uint32  //存在时间 秒
	ForwardNextHopAS uint32  //下一跳自治域号码 0
	ForwardMetric1   uint32  //度量衡(跃点数)，根据 ForwardProto 不同意义不同。
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

func Gways() []netip.Addr {
	ret := []netip.Addr{}
L1:
	for _, r := range getRoutes() {
		ip := netip.AddrFrom4(r.ForwardNextHop)
		for _, addr := range ret {
			if ip == localhost || addr == ip {
				continue L1
			}
		}
		ret = append(ret, ip)
	}
	return ret
}

func getRoutes() []RouteRow {
	iphlpapi := syscall.NewLazyDLL("iphlpapi.dll")
	buf := make([]byte, 4+unsafe.Sizeof(RouteRow{}))
	buf_len := uint32(len(buf))
	getIpForwardTable := iphlpapi.NewProc("GetIpForwardTable")
	var r1 uintptr
	for i := 0; i < 6; i++ {
		buf = make([]byte, buf_len)
		r1, _, _ = getIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&buf_len)), 0)
		if syscall.Errno(r1) == syscall.ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		break
	}
	if r1 != 0 {
		return []RouteRow{}
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	routes := make([]RouteRow, num)
	sr := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(num)
	rowSize := unsafe.Sizeof(RouteRow{})
	// 安全检查
	if len(buf) < int((unsafe.Sizeof(num) + rowSize*uintptr(num))) {
		return []RouteRow{}
	}
	for i := uint32(0); i < num; i++ {
		pr := unsafe.Pointer(sr + (rowSize * uintptr(i)))
		routes[i] = *((*RouteRow)(pr))
	}
	return routes
}

// Deprecated: Use common.Gways instead.
func GetGateways() []net.IP {
	ret := []net.IP{}
L1:
	for _, r := range getRoutes() {
		ip := netip.AddrFrom4(r.ForwardNextHop)
		if ip == localhost {
			continue
		}
		for _, addr := range ret {
			addrI, _ := netip.AddrFromSlice(addr)
			if addrI == ip {
				continue L1
			}
		}
		ret = append(ret, net.IPv4(r.ForwardNextHop[0], r.ForwardNextHop[1], r.ForwardNextHop[2], r.ForwardNextHop[3]))
	}
	return ret
}
