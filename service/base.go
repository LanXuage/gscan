package service

import "github.com/LanXuage/gscan/common"

var logger = common.GetLogger()

const (
	GSRULE_TYPE_NORMAL_TCP uint8 = 0
	GSRULE_TYPE_NORMAL_UDP uint8 = 1
)

type GScanRuleItem struct {
	DataType uint8
	Len      uint32
	Data     []byte
}

type GScanRule struct {
	Version  uint8
	RuleType uint8
	Len      int8
	Items    []GScanRuleItem
}
