package icmp_test

import (
	"gscan/common"
	"gscan/icmp"
	"testing"
	"time"
)

func TestICMPScanner(t *testing.T) {
	i := icmp.New()
	defer i.Close()
	ipList := []string{"13.107.21.200", "120.78.212.208", "183.6.50.84", "192.168.31.1", "192.168.31.100", "172.25.156.84"}
	tmp := common.IPList2NetIPList(ipList)
	go func() {
		for res := range i.ScanList(tmp) {
			t.Log(res)
		}
	}()
	time.Sleep(time.Second * 5)
	a, _ := (*i.Results).Get("13.107.21.200")
	t.Log(a)
}
