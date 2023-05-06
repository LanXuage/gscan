package cmd_test

import (
	"gscan/cmd"
	"testing"
)

func TestParseAddr(t *testing.T) {
	t.Log(cmd.ParseAddr("192.168.1.1-28"))
	t.Log(cmd.ParseAddr("fe80::215:5dff:fefa:da23-da34"))
}
