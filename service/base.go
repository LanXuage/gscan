package service

import "github.com/LanXuage/gscan/common"

var logger = common.GetLogger()

const (
	GSRULE_TYPE_TCP     uint8 = 0
	GSRULE_TYPE_UDP     uint8 = 1
	GSRULE_TYPE_TCP_MUX uint8 = 2
	GSRULE_TYPE_UDP_MUX uint8 = 3

	GSRULE_DATA_TYPE_MATCH uint8 = 0
)

type GScanRuleItem struct {
	DataType uint8
	// Len      uint32
	Data []byte
}

type GScanRule struct {
	Version  uint8
	RuleType uint8
	// Len      uint8
	Items []GScanRuleItem
}

type ScanEnv struct {
	LastResp []byte
	Vals     map[string][]byte
}
