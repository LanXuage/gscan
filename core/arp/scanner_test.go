package arp_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/LanXuage/gscan/core/arp"
)

func TestARPScanner(t *testing.T) {
	a := arp.GetARPScanner()
	ip, _ := netip.ParseAddr("192.168.48.1")
	task := a.Scan([]netip.Addr{ip})
	for arpResult := range task.GetResults(time.Second * 10) {
		t.Logf("aarpResult: %v\n", arpResult)
	}
	t.Log("aaaaaaaaaa")
	task = a.ScanLocalNet()
	for arpResult := range task.GetResults(time.Second * 10) {
		t.Logf("aarpResult: %v\n", arpResult)
	}
}
