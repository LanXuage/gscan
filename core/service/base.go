package service

import (
	"github.com/LanXuage/gscan/arp"
	"github.com/LanXuage/gscan/common"
)

var logger = common.GetLogger()

var arpInstance = arp.GetARPScanner()

type ScanEnv struct {
	LastResp []byte
	Vals     map[string][]byte
}

var serviceInstance = newServiceScanner()

func GetServiceScanner() *ServiceScanner {
	return serviceInstance
}
