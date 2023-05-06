package common_test

import (
	"gscan/common"
	"testing"
)

func TestGetGateways(t *testing.T) {
	a := common.Gways()
	t.Log(a[0])
}
