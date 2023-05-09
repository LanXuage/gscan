package cmd_test

import (
	"testing"

	"github.com/LanXuage/gscan/cmd"
)

func TestParseAddr(t *testing.T) {
	t.Log(cmd.ParseAddr("192.168.1.1-28"))
	t.Log(cmd.ParseAddr("fe80::215:5dff:fefa:da23-da34"))
}
