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

func TestIsRedis(t *testing.T) {
	buf := []byte{42, 51, 13, 10, 36, 52, 13, 10, 72, 71, 69, 84, 13, 10, 36, 51, 54, 13, 10, 56, 97, 100, 48, 101, 56, 99, 97, 45, 101, 97, 49, 57, 45, 52, 50, 97, 57, 45, 98, 51, 55, 48, 45, 98, 99, 97, 102, 102, 50, 55, 54, 55, 98, 56, 54, 13, 10, 36, 52, 13, 10, 99, 97, 114, 116, 13, 10, 103, 58, 32, 34, 51, 49, 117, 50, 107, 97, 100, 98, 108, 113, 53, 106, 34, 13, 10, 99, 111, 110, 116, 101, 110, 116, 45, 108, 101, 110, 103, 116, 104, 58, 32, 49, 57, 57, 13, 10, 118, 97, 114, 121, 58, 32, 65, 99, 99, 101, 112, 116, 45, 69, 110, 99, 111, 100, 105, 110, 103, 13, 10, 100, 97, 116, 101, 58, 32, 87, 101, 100, 44, 32, 48, 51, 32, 74, 117, 108, 32, 50, 48, 50, 52, 32, 49, 55, 58, 52, 54, 58, 49, 55, 32, 71, 77, 84, 13, 10, 120, 45, 101, 110, 118, 111, 121, 45, 117, 112, 115, 116, 114, 101, 97, 109, 45, 115, 101, 114, 118, 105, 99, 101, 45, 116, 105, 109, 101, 58, 32, 51, 13, 10, 115, 101, 114, 118, 101, 114, 58, 32, 101, 110, 118, 111, 121, 13, 10, 13, 10, 91, 34, 90, 65, 82, 34, 44, 34, 73, 83, 75, 34, 44, 34, 73, 76, 83, 34, 44, 34, 82, 79, 78, 34, 44, 34, 71, 66, 80, 34, 44, 34, 66, 82, 76, 34, 44, 34}
	rbuf := []byte{36, 45, 49, 13, 10, 1, 0, 15, 0, 3, 89, 130, 0, 32, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 17, 170, 173, 222, 0, 0, 141, 2, 1, 1, 1, 0, 101, 112, 116, 45, 114, 97, 110, 103, 101, 115, 58, 32, 98, 121, 116, 101, 115, 13, 10, 108, 97, 115, 116, 45, 109, 111, 100, 105, 102, 105, 101, 100, 58, 32, 70, 114, 105, 44, 32, 48, 55, 32, 74, 117, 110, 32, 50, 48, 50, 52, 32, 48, 48, 58, 53, 55}
	assert.True(t, isRedis(buf))
	assert.True(t, isRedis(rbuf))
}
