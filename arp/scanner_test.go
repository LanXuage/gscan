package arp_test

import (
	"testing"
	"time"

	"github.com/LanXuage/gscan/arp"
)

func Test_ARPScanner(t *testing.T) {
	a := arp.GetARPScanner()
	defer a.Close()
	go func() {
		// for result := range a.ScanLocalNet() {
		// 	t.Log(result)
		// }
	}()
	time.Sleep(5 * time.Second)
	t.Log(a.AHMap.Items())
}
