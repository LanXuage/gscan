package service_test

import (
	"regexp"
	"testing"

	"github.com/LanXuage/gscan/common"
)

func TestRe(t *testing.T) {
	data1 := []byte{0xff, 0x6a}
	data2 := []byte{0xc3, 0xbf}
	data3 := []byte{0xbf, 0xc3}
	rStr := `^\xff`
	r := regexp.MustCompile(string(common.Bytes2Runes([]byte(rStr))))
	if r.MatchString(string(common.Bytes2Runes(data1))) != true {
		t.Error("byte no match")
	}
	if r.MatchString(string(common.Bytes2Runes(data2))) != false {
		t.Error("byte no match")
	}
	if r.MatchString(string(common.Bytes2Runes(data3))) != false {
		t.Error("byte no match")
	}
	data4 := []byte{0x20, 0xfe}
	rStr = `\s\xfe`
	r = regexp.MustCompile(string(common.Bytes2Runes([]byte(rStr))))
	t.Log(r.MatchString(string(common.Bytes2Runes(data4))))
}
