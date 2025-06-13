package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"

	"github.com/grafana/beyla/v2/pkg/config"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

const (
	tcpSend = 1
	tcpRecv = 0
)

func TestTCPReqSQLParsing(t *testing.T) {
	sql := randomStringWithSub("SELECT * FROM accounts ")
	r := makeTCPReq(sql, tcpSend, 343534, 8080, 2000)
	op, table, sql := detectSQL(sql)
	assert.Equal(t, op, "SELECT")
	assert.Equal(t, table, "accounts")
	s := TCPToSQLToSpan(&r, op, table, sql, request.DBGeneric)
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.Host)
	assert.NotEmpty(t, s.Peer)
	assert.Equal(t, s.HostPort, 8080)
	assert.Greater(t, s.End, s.Start)
	assert.True(t, strings.Contains(s.Statement, "SELECT * FROM accounts "))
	assert.Equal(t, "SELECT", s.Method)
	assert.Equal(t, "accounts", s.Path)
	assert.Equal(t, request.EventTypeSQLClient, s.Type)
}

func TestTCPReqParsing(t *testing.T) {
	sql := "Not a sql or any known protocol"
	r := makeTCPReq(sql, tcpSend, 343534, 8080, 2000)
	op, table, _ := detectSQL(sql)
	assert.Empty(t, op)
	assert.Empty(t, table)
	assert.NotNil(t, r)
}

func TestSQLDetection(t *testing.T) {
	for _, s := range []string{"SELECT * from accounts", "SELECT/*My comment*/ * from accounts", "--UPDATE accounts SET", "DELETE++ from accounts ", "INSERT into accounts ", "CREATE table accounts ", "DROP table accounts ", "ALTER table accounts"} {
		surrounded := randomStringWithSub(s)
		op, table, _ := detectSQL(s)
		assert.NotEmpty(t, op)
		assert.NotEmpty(t, table)
		op, table, _ = detectSQL(surrounded)
		assert.NotEmpty(t, op)
		assert.NotEmpty(t, table)
	}
}

func TestSQLDetectionFails(t *testing.T) {
	for _, s := range []string{"SELECT", "UPDATES{}", "DELETE {} ", "INSERT// into accounts "} {
		op, table, _ := detectSQL(s)
		assert.False(t, validSQL(op, table, request.DBGeneric))
		surrounded := randomStringWithSub(s)
		op, table, _ = detectSQL(surrounded)
		assert.False(t, validSQL(op, table, request.DBGeneric))
	}
}

func TestSQLDetectionDoesntFailForDetectedKind(t *testing.T) {
	for _, s := range []string{"SELECT", "DELETE {} "} {
		op, table, _ := detectSQL(s)
		assert.True(t, validSQL(op, table, request.DBPostgres))
	}
}

// Test making sure that issue https://github.com/grafana/beyla/issues/854 is fixed
func TestReadTCPRequestIntoSpan_Overflow(t *testing.T) {
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}

	tri := TCPRequestInfo{
		Len: 340,
		// this byte array contains select * from foo
		// rest of the array is invalid UTF-8 and would cause that strings.ToUpper
		// returns a string longer than 256. That's why we are providing
		// our own asciiToUpper implementation in detectSQL function
		Buf: [256]byte{
			74, 39, 133, 207, 240, 83, 124, 225, 227, 163, 3, 23, 253, 254, 18, 12, 77, 143, 198, 122,
			123, 67, 221, 225, 10, 233, 220, 36, 65, 35, 25, 251, 88, 197, 107, 99, 25, 247, 195, 216,
			245, 107, 26, 144, 75, 78, 24, 70, 136, 173, 198, 79, 148, 232, 19, 253, 185, 169, 213, 97,
			85, 119, 210, 114, 92, 26, 226, 241, 33, 16, 199, 78, 88, 108, 8, 211, 76, 188, 8, 170, 68,
			128, 108, 194, 67, 240, 144, 132, 50, 191, 136, 130, 52, 210, 166, 212, 17, 179, 144, 138,
			101, 98, 119, 16, 125, 99, 161, 176, 9, 25, 218, 236, 219, 22, 144, 91, 158, 146, 14, 243,
			177, 58, 40, 139, 158, 33, 3, 91, 63, 70, 85, 20, 222, 206, 211, 152, 216, 53, 177, 125, 204,
			219, 157, 151, 222, 184, 241, 193, 111, 22, 242, 185, 126, 159, 53, 181,
			's', 'e', 'l', 'e', 'c', 't', ' ', '*', ' ', 'f', 'r', 'o', 'm', ' ', 'f', 'o', 'o',
			0, 17, 111, 111, 133, 13, 221,
			135, 126, 159, 234, 95, 233, 172, 96, 241, 140, 96, 71, 100, 223, 73, 74, 117, 239, 170, 154,
			148, 167, 122, 215, 170, 51, 236, 146, 5, 61, 208, 74, 230, 243, 106, 222, 52, 138, 202, 39,
			122, 180, 232, 43, 217, 86, 220, 38, 106, 141, 188, 27, 133, 156, 96, 107, 180, 178, 20, 62,
			169, 193, 172, 206, 225, 219, 112, 52, 115, 32, 147, 192, 127, 211, 129, 241,
		},
	}

	cfg := config.EBPFTracer{HeuristicSQLDetect: true}

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))
	span, ignore, err := ReadTCPRequestIntoSpan(&cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	require.False(t, ignore)

	assert.Equal(t, request.EventTypeSQLClient, span.Type)
	assert.Equal(t, "SELECT", span.Method)
	assert.Equal(t, "foo", span.Path)
}

func TestRedisDetection(t *testing.T) {
	for _, s := range []string{
		`*2|$3|GET|$5|beyla|`,
		`*2|$7|HGETALL|$16|users_sessions`,
		`*8|$4|name|$4|John|`,
		`+OK|`,
		"-ERR ",
		":123|",
		"-WRONGTYPE ",
		"-MOVED ",
	} {
		lines := strings.Split(s, "|")
		test := strings.Join(lines, "\r\n")
		assert.True(t, isRedis([]uint8(test)))
		assert.True(t, isRedisOp([]uint8(test)))
	}

	for _, s := range []string{
		"",
		`*2`,
		`*$7`,
		`+OK`,
		"-ERR",
		"-WRONGTYPE",
	} {
		lines := strings.Split(s, "|")
		test := strings.Join(lines, "\r\n")
		assert.False(t, isRedis([]uint8(test)))
		assert.False(t, isRedisOp([]uint8(test)))
	}
}

func TestTCPReqKafkaParsing(t *testing.T) {
	// kafka message
	b := []byte{0, 0, 0, 94, 0, 1, 0, 11, 0, 0, 0, 224, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 6, 64, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0}
	r := makeTCPReq(string(b), tcpSend, 343534, 8080, 2000)
	k, err := ProcessKafkaRequest(b)
	assert.NoError(t, err)
	s := TCPToKafkaToSpan(&r, k)
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.Host)
	assert.NotEmpty(t, s.Peer)
	assert.Equal(t, s.HostPort, 8080)
	assert.Greater(t, s.End, s.Start)
	assert.Equal(t, "process", s.Method)
	assert.Equal(t, "important", s.Path)
	assert.Equal(t, "sarama", s.Statement)
	assert.Equal(t, request.EventTypeKafkaClient, s.Type)
}

const charset = "\\0\\1\\2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func randomStringWithSub(sub string) string {
	return fmt.Sprintf("%s%s%s", randomString(rand.Intn(10)), sub, randomString(rand.Intn(20)))
}

func makeTCPReq(buf string, direction int, peerPort, hostPort uint32, durationMs uint64) TCPRequestInfo {
	i := TCPRequestInfo{
		StartMonotimeNs: durationMs * 1000000,
		EndMonotimeNs:   durationMs * 2 * 1000000,
		Len:             uint32(len(buf)),
		Direction:       uint8(direction),
	}

	copy(i.Buf[:], buf)
	i.ConnInfo.S_addr[0] = 1
	i.ConnInfo.S_addr[1] = 0
	i.ConnInfo.S_addr[2] = 0
	i.ConnInfo.S_addr[3] = 127
	i.ConnInfo.S_port = uint16(peerPort)
	i.ConnInfo.D_addr[0] = 1
	i.ConnInfo.D_addr[1] = 0
	i.ConnInfo.D_addr[2] = 0
	i.ConnInfo.D_addr[3] = 127
	i.ConnInfo.D_port = uint16(hostPort)

	return i
}
