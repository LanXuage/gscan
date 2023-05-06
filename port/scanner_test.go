package port_test

import (
	"gscan/port"
	"net/netip"
	"testing"
)

func parseAddr(ip string) netip.Addr {
	addr, _ := netip.ParseAddr(ip)
	return addr
}

var ips = []netip.Addr{parseAddr("13.107.21.200"), parseAddr("120.78.212.208"),
	parseAddr("183.6.50.84"), parseAddr("192.168.31.1"), parseAddr("192.168.31.100"),
	parseAddr("14.119.104.189"), parseAddr("106.14.112.92"), parseAddr("192.168.1.9"),
	parseAddr("192.168.2.134"), parseAddr("192.168.2.110"), parseAddr("192.168.2.200"), parseAddr("8.210.214.182"),
}

func TestHalfTCPLocalNet(t *testing.T) {
	tcp := port.GetTCPScanner()
	timeoutCh := tcp.ScanLocalNet()
	for {
		select {
		case <-timeoutCh:
			return
		case result := <-tcp.ResultCh:
			t.Logf("%v", result)
		}
	}
}

func TestTCPLocalNet(t *testing.T) {
	tcp := port.GetTCPScanner()
	tcp.UseFullTCP = true
	timeoutCh := tcp.ScanLocalNet()
	for {
		select {
		case <-timeoutCh:
			return
		case result := <-tcp.ResultCh:
			t.Logf("%v\n", result)
		}
	}
}

func TestHalfTCPLocalNetAllPorts(t *testing.T) {
	// tcp := port.GetTCPScanner()
	// tcp.PortScanType = port.ALL_PORTS
	// timeoutCh := tcp.ScanLocalNet()
	// for {
	// 	select {
	// 	case <-timeoutCh:
	// 		return
	// 	case result := <-tcp.ResultCh:
	// 		t.Logf("%v", result)
	// 	}
	// }
}

func TestTCPLocalNetAllPorts(t *testing.T) {
	// tcp := port.GetTCPScanner()
	// tcp.UseFullTCP = true
	// tcp.PortScanType = port.ALL_PORTS
	// timeoutCh := tcp.ScanLocalNet()
	// for {
	// 	select {
	// 	case <-timeoutCh:
	// 		return
	// 	case result := <-tcp.ResultCh:
	// 		t.Logf("%v", result)
	// 	}
	// }
}

func TestScanIPs(t *testing.T) {
	tcp := port.GetTCPScanner()
	tcp.UseFullTCP = true
	tcp.PortScanType = port.DEFAULT_PORTS
	// tcp.PortScanType = port.ALL_PORTS
	// tcp.Timeout = 100 * time.Second
	timeoutCh := tcp.ScanMany(ips)
	for {
		select {
		case <-timeoutCh:
			return
		case result := <-tcp.ResultCh:
			t.Logf("ret: %v", result)
		}
	}
}

func TestUDP(t *testing.T) {
	// os.Setenv("GSCAN_LOG_LEVEL", "development")
	// p := port.New()
	// defer p.Close()

	// tmp := common.IPList2NetIPList(testIPList)

	// udp := p.UDPScan(tmp)

	// time.Sleep(udp.Timeout)

	// ip := []uint32{}
	// for ipUint32 := range udp.Results {
	// 	ip = append(ip, uint32(ipUint32))
	// }

	// t.Log(ip)

}

func TestNetip(t *testing.T) {
	ip, _ := netip.ParseAddr("172.25.17.0")
	t.Log(ip.IsValid())
	t.Log(ip.IsMulticast())
	t.Log(ip.IsUnspecified())
	t.Log(ip.IsGlobalUnicast())
	t.Log(ip.IsInterfaceLocalMulticast())
	t.Log(ip.IsLinkLocalMulticast())
	t.Log(ip.IsLinkLocalUnicast())
	t.Log(ip.IsLoopback())
	t.Log(ip.IsPrivate())
	t.Log(ip.Zone())
	t.Log(ip.BitLen())
	t.Log("-----------------")
	ip, _ = netip.ParseAddr("172.25.17.2")
	t.Log(ip.IsValid())
	t.Log(ip.IsMulticast())
	t.Log(ip.IsUnspecified())
	t.Log(ip.IsGlobalUnicast())
	t.Log(ip.IsInterfaceLocalMulticast())
	t.Log(ip.IsLinkLocalMulticast())
	t.Log(ip.IsLinkLocalUnicast())
	t.Log(ip.IsLoopback())
	t.Log(ip.IsPrivate())
	t.Log(ip.Zone())
	t.Log(ip.BitLen())
}
