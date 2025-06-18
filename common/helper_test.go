package common_test

import (
	"testing"

	"github.com/LanXuage/gscan/common"
)

func TestExec(t *testing.T) {
	t.Log(string(common.Exec("ls")))
	t.Log(string(common.Exec("ls -a")))
}

func BenchmarkIsSameLAN(b *testing.B) {
	for n := 0; n < b.N; n++ {
	}
}

func BenchmarkCheckIPisIPNet(b *testing.B) {
	for n := 0; n < b.N; n++ {
	}
}

func TestRunesAndBytes(t *testing.T) {
	b := []byte{0xff, 0xfe, 0x34, 0x6a, 0x64}
	r := common.Bytes2Runes(b)
	ba := common.Runes2Bytes(r)
	t.Log(b)
	t.Log(r)
	t.Log(ba)
	for _, i := range string(b) {
		t.Log(i)
	}
	t.Log("=====")
	for _, i := range string(r) {
		t.Log(i)
	}
}
