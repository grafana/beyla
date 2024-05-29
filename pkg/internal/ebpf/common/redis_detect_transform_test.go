package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type crlfTest struct {
	testStr string
	result  bool
}

func TestCRLFMatching(t *testing.T) {
	for _, ts := range []crlfTest{
		{testStr: "Not a sql or any known protocol", result: false},
		{testStr: "Not a sql or any known protocol\r\n", result: true},
		{testStr: "123\r\n", result: false},
		{testStr: "\r\n", result: true},
		{testStr: "\n", result: false},
		{testStr: "\r", result: false},
		{testStr: "", result: false},
	} {
		res := crlfTerminatedMatch([]uint8(ts.testStr), func(c uint8) bool {
			return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == ' ' || c == '-' || c == '_'
		})
		assert.Equal(t, res, ts.result)

	}
}
