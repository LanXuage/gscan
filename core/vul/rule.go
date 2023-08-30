package vul

import (
	"github.com/LanXuage/gscan/common"
)

func getRules() *[]common.GScanRule {
	return &[]common.GScanRule{
		{
			Version:  0,
			RuleType: common.GSRULE_TYPE_TCP_MUX,
			Items: []common.GScanRuleItem{
				{
					DataType: common.GSRULE_DATA_TYPE_MATCH,
					Data:     []byte{83, 83, 72, 45, 50, 46, 48, 45, 79, 112, 101, 110, 83, 83, 72, 95, 40, 63, 80, 60, 118, 101, 114, 115, 105, 111, 110, 62, 92, 100, 43, 40, 63, 58, 92, 46, 92, 100, 43, 41, 42, 63, 41, 40, 63, 80, 60, 117, 112, 100, 97, 116, 101, 62, 112, 92, 100, 43, 41, 92, 115},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_PROTOCOL,
					Data:     []byte{115, 115, 104},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_CPE23,
					Data:     []byte{97, 58, 111, 112, 101, 110, 98, 115, 100, 58, 111, 112, 101, 110, 115, 115, 104, 58, 60, 118, 101, 114, 115, 105, 111, 110, 62, 58, 60, 117, 112, 100, 97, 116, 101, 62},
				},
			},
		},
	}
}
