package common_test

import (
	"testing"

	"github.com/LanXuage/gscan/common"
)

func TestGetGateways(t *testing.T) {
	a := common.Gways()
	t.Log(a[0])
}
