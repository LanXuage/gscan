package icmp_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/icmp"
)

func TestICMPScanner(t *testing.T) {
	i := icmp.GetICMPScanner()
	defer i.Close()
	i.Init()
	ipList := []string{"13.107.21.200", "120.78.212.208", "183.6.50.84", "192.168.31.1", "192.168.31.100", "172.25.156.84"}
	tmp := common.IPList2NetIPList(ipList)

	timeoutCh := i.ScanList(tmp)
	for {
		select {
		case result := <-i.ResultCh:
			if result.IsActive {
				t.Logf("%s\t\tAlive\n", result.IP)
			}
		case <-timeoutCh:
			return
		}
	}
}

func TestTTL(t *testing.T) {
	i := icmp.GetICMPScanner()
	defer i.Close()
	i.Choice = 2
	i.Init()
	ip, _ := netip.ParseAddr("106.14.112.92")

	timeoutCh := i.ScanOne(ip)
	for {
		select {
		case result := <-i.TResultCh:
			fmt.Printf("2111")
			t.Logf("%s\n", result.IP)
		case <-timeoutCh:
			return
		}
	}

}
