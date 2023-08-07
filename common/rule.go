package common

const (
	GSRULE_TYPE_TCP     uint8 = 0
	GSRULE_TYPE_UDP     uint8 = 1
	GSRULE_TYPE_TCP_MUX uint8 = 2
	GSRULE_TYPE_UDP_MUX uint8 = 3
	GSRULE_TYPE_CODE    uint8 = 4

	GSRULE_DATA_TYPE_MATCH    uint8 = 0
	GSRULE_DATA_TYPE_SEND     uint8 = 1
	GSRULE_DATA_TYPE_SEND_MUX uint8 = 2
	GSRULE_DATA_TYPE_PROTOCOL uint8 = 3
	GSRULE_DATA_TYPE_CPE      uint8 = 4
	GSRULE_DATA_TYPE_CPE23    uint8 = 5
	GSRULE_DATA_TYPE_CVE      uint8 = 6
	GSRULE_DATA_TYPE_CNVD     uint8 = 7
	GSRULE_DATA_TYPE_CNNVD    uint8 = 8
	GSRULE_DATA_TYPE_GO       uint8 = 9
	GSRULE_DATA_TYPE_PY2      uint8 = 10
	GSRULE_DATA_TYPE_PY       uint8 = 11
	GSRULE_DATA_TYPE_SH       uint8 = 12
	GSRULE_DATA_TYPE_JAR      uint8 = 13
	GSRULE_DATA_TYPE_CLASS    uint8 = 14
	GSRULE_DATA_TYPE_JS       uint8 = 15
	GSRULE_DATA_TYPE_PHP      uint8 = 16
	GSRULE_DATA_TYPE_PERL     uint8 = 17
	GSRULE_DATA_TYPE_OTHER    uint8 = 255
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
