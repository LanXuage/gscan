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

	d := []byte{83, 83, 72, 45, 50, 46, 48, 45, 79, 112, 101, 110, 83, 83, 72, 95, 56, 46, 57, 112, 49, 32, 85, 98, 117, 110, 116, 117, 45, 51, 117, 98, 117, 110, 116, 117, 48, 46, 49, 13, 10}
	rrStr := "SSH-2.0-OpenSSH_(?P<version>\\d+(?:\\.\\d+)*?)(?P<update>p\\d+)\\s"
	rr := regexp.MustCompile(string(common.Bytes2Runes([]byte(rrStr))))
	t.Log(rr.FindAllStringSubmatch(string(common.Bytes2Runes(d)), -1))

}
