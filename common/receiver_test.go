package common_test

import (
	"gscan/common"
	"strconv"
	"testing"
	"time"

	"github.com/google/gopacket"
)

type TestRes struct {
	Name string
}

func test(packet gopacket.Packet) interface{} {
	return TestRes{
		Name: "test",
	}
}

func TestReceiver(t *testing.T) {
	r := common.GetReceiver()
	rCh := r.Register("test", test)
	time.Sleep(1 * time.Second)
	for r := range rCh {
		if res, ok := r.(TestRes); ok {
			t.Logf("got res %s", res.Name)
			return
		}
	}
}

func BenchmarkReceiver(b *testing.B) {
	r := common.GetReceiver()
	for n := 0; n < b.N; n++ {
		r.Register("test"+strconv.Itoa(n), test)
	}
}
