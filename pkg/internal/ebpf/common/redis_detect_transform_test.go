package ebpfcommon

import (
	"fmt"
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

func TestRedisParsing(t *testing.T) {
	proper := fmt.Sprintf("*2\r\n$3\r\nGET\r\n$5\r\n%s", "beyla")

	op, text, ok := parseRedisRequest(proper)
	assert.True(t, ok)
	assert.Equal(t, "GET", op)
	assert.Equal(t, "GET beyla ", text)

	weird := fmt.Sprintf("*2\r\nGET\r\n%s", "beyla")
	op, text, ok = parseRedisRequest(weird)
	assert.True(t, ok)
	assert.Equal(t, "", op)
	assert.Equal(t, "", text)

	unknown := fmt.Sprintf("2\r\nGET\r\n%s", "beyla")
	op, text, ok = parseRedisRequest(unknown)
	assert.True(t, ok)
	assert.Equal(t, "", op)
	assert.Equal(t, "", text)

	op, text, ok = parseRedisRequest("2")
	assert.False(t, ok)
	assert.Equal(t, "", op)
	assert.Equal(t, "", text)

	multi := fmt.Sprintf("*4\r\n$6\r\nclient\r\n$7\r\nsetinfo\r\n$8\r\nLIB-NAME\r\n$19\r\n%s(,go1.22.2)\r\n*4\r\n$6\r\nclient\r\n$7\r\nsetinfo\r\n$7\r\nLIB-VER\r\n$5\r\n9.5.1\r\n", "go-redis")
	op, text, ok = parseRedisRequest(multi)
	assert.True(t, ok)
	assert.Equal(t, "client", op)
	assert.Equal(t, "client setinfo LIB-NAME go-redis(,go1.22.2) ; client setinfo LIB-VER 9.5.1 ", text)

	hmset := []byte{42, 52, 13, 10, 36, 53, 13, 10, 72, 77, 83, 69, 84, 13, 10, 36, 51, 54, 13, 10, 48, 99, 57, 102, 97, 56, 97, 97, 45, 50, 56, 49, 102, 45, 49, 49, 101, 102, 45, 57, 55, 98, 57, 45, 98, 101, 57, 54, 48, 48, 99, 97, 48, 102, 50, 55, 13, 10, 36, 52, 13, 10, 99, 97, 114, 116, 13, 10, 36, 53, 52, 13, 10, 10, 36, 48, 99, 57, 102, 97, 56, 97, 97, 45, 50, 56, 49, 102, 45, 49, 49, 101, 102, 45, 57, 55, 98, 57, 45, 98, 101, 57, 54, 48, 48, 99, 97, 48, 102, 50, 55, 18, 14, 10, 10, 79, 76, 74, 67, 69, 83, 80, 67, 55, 90, 16, 5, 13, 10, 0, 10, 72, 81, 84, 71, 87, 71, 80, 78, 72, 52, 16, 1, 13, 10, 0, 10, 49, 89, 77, 87, 87, 78, 49, 78, 52, 79, 16, 5, 13, 10, 0, 10, 10, 57, 83, 73, 81, 84, 56, 84, 79, 74, 79, 16, 5, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	op, text, ok = parseRedisRequest(string(hmset))

	assert.True(t, ok)
	assert.Equal(t, "HMSET", op)
	assert.Equal(t, "HMSET 0c9fa8aa-281f-11ef-97b9-be9600ca0f27 cart ", text)
}
