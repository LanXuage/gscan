package common_test

import (
	"gscan/common"
	"net"
	"testing"
)

var ip = net.ParseIP("192.168.1.2").To4()
var inIp = net.ParseIP("192.168.1.1").To4()
var outIp = net.ParseIP("192.168.0.45").To4()
var mask = common.IP2Uint32(net.ParseIP("255.255.255.0").To4())

func TestCheckIPisIPNet(t *testing.T) {
	if !common.CheckIPisIPNet(ip, inIp, mask) {
		t.Fatalf("Expected %v, Got %v, ip %d, inIp %d, mask %d", true, false, ip, inIp, mask)
	}
	if common.CheckIPisIPNet(ip, outIp, mask) {
		t.Fatalf("Expected %v, Got %v, ip %d, inIp %d, mask %d", false, true, ip, outIp, mask)
	}
}

func TestIsSameLAN(t *testing.T) {
	if !common.IsSameLAN(ip, inIp, mask) {
		t.Fatalf("Expected %v, Got %v, ip %d, inIp %d, mask %d", true, false, ip, inIp, mask)
	}
	if common.IsSameLAN(ip, outIp, mask) {
		t.Fatalf("Expected %v, Got %v, ip %d, inIp %d, mask %d", false, true, ip, outIp, mask)
	}
}

func TestExec(t *testing.T) {
	t.Log(string(common.Exec("ls")))
	t.Log(string(common.Exec("ls -a")))
}

func BenchmarkIsSameLAN(b *testing.B) {
	for n := 0; n < b.N; n++ {
		common.IsSameLAN(ip, inIp, mask)
		common.IsSameLAN(ip, outIp, mask)
	}
}

func BenchmarkCheckIPisIPNet(b *testing.B) {
	for n := 0; n < b.N; n++ {
		common.CheckIPisIPNet(ip, inIp, mask)
		common.CheckIPisIPNet(ip, outIp, mask)
	}
}
