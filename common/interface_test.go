package common_test

import (
	"gscan/common"
	"testing"
)

func TestGetActiveInterfaces(t *testing.T) {
	t.Log(common.GetActiveInterfaces())
}

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
