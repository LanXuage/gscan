package service

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
		{
			Version:  0,
			RuleType: common.GSRULE_TYPE_TCP_MUX,
			Items: []common.GScanRuleItem{
				{
					DataType: common.GSRULE_DATA_TYPE_MATCH,
					Data:     []byte{94, 83, 245, 198, 26, 123},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_PROTOCOL,
					Data:     []byte{49, 99, 45, 115, 101, 114, 118, 101, 114},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_CPE23,
					Data:     []byte{97, 58, 49, 99, 58, 49, 99, 92, 58, 101, 110, 116, 101, 114, 112, 114, 105, 115, 101, 58, 45},
				},
			},
		},
		{
			Version:  0,
			RuleType: common.GSRULE_TYPE_TCP_MUX,
			Items: []common.GScanRuleItem{
				{
					DataType: common.GSRULE_DATA_TYPE_MATCH,
					Data:     []byte{94, 4, 0, 251, 255, 76, 65, 80, 75},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_PROTOCOL,
					Data:     []byte{51, 99, 120, 45, 116, 117, 110, 110, 101, 108},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_CPE23,
					Data:     []byte{97, 58, 51, 99, 120, 58, 51, 99, 120, 58, 45},
				},
			},
		},
		{
			Version:  0,
			RuleType: common.GSRULE_TYPE_TCP_MUX,
			Items: []common.GScanRuleItem{
				{
					DataType: common.GSRULE_DATA_TYPE_MATCH,
					Data:     []byte{94, 92, 42, 32, 65, 67, 65, 80, 32, 92, 40, 73, 77, 80, 76, 69, 77, 69, 78, 84, 65, 84, 73, 79, 78, 32, 92, 34, 67, 111, 109, 109, 117, 110, 105, 71, 97, 116, 101, 32, 80, 114, 111, 32, 65, 67, 65, 80, 32, 40, 92, 100, 91, 45, 46, 92, 119, 93, 43, 41, 92, 34, 92, 41},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_PROTOCOL,
					Data:     []byte{97, 99, 97, 112},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_CPE23,
					Data:     []byte{97, 58, 99, 111, 109, 109, 117, 110, 105, 103, 97, 116, 101, 58, 99, 111, 109, 109, 117, 110, 105, 103, 97, 116, 101, 95, 112, 114, 111},
				},
			},
		},
		{
			Version:  0,
			RuleType: common.GSRULE_TYPE_TCP_MUX,
			Items: []common.GScanRuleItem{
				{
					DataType: common.GSRULE_DATA_TYPE_MATCH,
					Data:     []byte{94, 65, 67, 77, 80, 32, 83, 101, 114, 118, 101, 114, 32, 86, 101, 114, 115, 105, 111, 110, 32, 40, 63, 80, 60, 118, 101, 114, 115, 105, 111, 110, 62, 91, 92, 119, 46, 95, 45, 93, 43, 41},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_PROTOCOL,
					Data:     []byte{97, 99, 109, 112},
				},
			},
		},
		{
			Version:  0,
			RuleType: common.GSRULE_TYPE_TCP_MUX,
			Items: []common.GScanRuleItem{
				{
					DataType: common.GSRULE_DATA_TYPE_MATCH,
					Data:     []byte{94, 65, 115, 116, 101, 114, 105, 115, 107, 32, 67, 97, 108, 108, 32, 77, 97, 110, 97, 103, 101, 114, 47, 40, 63, 80, 60, 118, 101, 114, 115, 105, 111, 110, 62, 91, 92, 100, 46, 93, 43, 41},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_PROTOCOL,
					Data:     []byte{97, 115, 116, 101, 114, 105, 115, 107},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_CPE23,
					Data:     []byte{97, 58, 100, 105, 103, 105, 117, 109, 58, 97, 115, 116, 101, 114, 105, 115, 107, 58, 60, 118, 101, 114, 115, 105, 111, 110, 62},
				},
			},
		},
		{
			Version:  0,
			RuleType: common.GSRULE_TYPE_TCP,
			Items: []common.GScanRuleItem{
				{
					DataType: common.GSRULE_DATA_TYPE_SEND_MUX,
					Data:     []byte{71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 48, 13, 10, 13, 10},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_MATCH,
					Data:     []byte{83, 101, 114, 118, 101, 114, 92, 115, 42, 63, 58, 92, 115, 42, 63, 110, 103, 105, 110, 120, 92, 47, 40, 63, 80, 60, 118, 101, 114, 115, 105, 111, 110, 62, 92, 100, 43, 63, 40, 63, 58, 92, 46, 92, 100, 43, 63, 41, 42, 63, 41, 91, 94, 92, 100, 92, 46, 93},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_PROTOCOL,
					Data:     []byte{104, 116, 116, 112},
				},
				{
					DataType: common.GSRULE_DATA_TYPE_CPE23,
					Data:     []byte{97, 58, 102, 53, 58, 110, 103, 105, 110, 120, 58, 60, 118, 101, 114, 115, 105, 111, 110, 62},
				},
			},
		},
	}
}
