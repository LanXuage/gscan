package common_test

import (
	"testing"

	"github.com/LanXuage/gscan/common"
)

func TestGetActiveIfaces(t *testing.T) {
	ifaces := common.GetActiveIfaces()
	start := (*ifaces)[0].Mask.Addr()
	for {
		start = start.Next()
		if !start.IsValid() || !(*ifaces)[0].Mask.Contains(start) {
			break
		}
		t.Log(start)
	}
}
