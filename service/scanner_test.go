package service_test

import (
	"regexp"
	"testing"
)

func TestRe(t *testing.T) {
	data := []byte{0xff, 0xff, 0x6a}
	str := string(data)
	t.Log(str)
	rStr := "j"
	r := regexp.MustCompile(rStr)
	t.Log(r.MatchString(str))
	rStr = `\xff`
	r = regexp.MustCompile(rStr)
	t.Log(r.Match(data))
}
