package ebpfcommon

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/request"
)

const (
	tcpSend = 1
	tcpRecv = 0
)

func TestTCPReqSQLParsing(t *testing.T) {
	sql := randomStringWithSub("SELECT * FROM accounts ")
	r := makeTCPReq(sql, tcpSend, 343534, 8080, 2000)
	sqlIndex := isSQL(sql)
	assert.GreaterOrEqual(t, sqlIndex, 0)
	s := TCPToSQLToSpan(&r, sql[sqlIndex:])
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

func TestSQLDetection(t *testing.T) {
	for _, s := range []string{"SELECT", "UPDATE", "DELETE", "INSERT", "CREATE", "DROP", "ALTER"} {
		surrounded := randomStringWithSub(s)
		assert.GreaterOrEqual(t, isSQL(surrounded), 0)
		assert.GreaterOrEqual(t, isSQL(s), 0)
	}
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
