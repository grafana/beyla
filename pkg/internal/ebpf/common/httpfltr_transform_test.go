package ebpfcommon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/request"
)

func TestHTTPInfoParsing(t *testing.T) {
	t.Run("Test basic parsing", func(t *testing.T) {
		tr := makeHTTPInfo("POST", "/users", "127.0.0.1", "127.0.0.2", 12345, 8080, 200, 5)
		s := httpInfoToSpan(&tr)
		assertMatchesInfo(t, &s, "POST", "/users", "127.0.0.1", "127.0.0.2", 8080, 200, 5)
	})

	t.Run("Test empty URL", func(t *testing.T) {
		tr := makeHTTPInfo("POST", "", "127.0.0.1", "127.0.0.2", 12345, 8080, 200, 5)
		s := httpInfoToSpan(&tr)
		assertMatchesInfo(t, &s, "POST", "", "127.0.0.1", "127.0.0.2", 8080, 200, 5)
	})

	t.Run("Test parsing with URL parameters", func(t *testing.T) {
		tr := makeHTTPInfo("POST", "/users?query=1234", "127.0.0.1", "127.0.0.2", 12345, 8080, 200, 5)
		s := httpInfoToSpan(&tr)
		assertMatchesInfo(t, &s, "POST", "/users", "127.0.0.1", "127.0.0.2", 8080, 200, 5)
	})
}

func TestMethodURLParsing(t *testing.T) {
	for _, s := range []string{
		"GET /test ",
		"GET /test\r\n",
		"GET /test\r",
		"GET /test\n",
		"GET /test",
		"GET /test/test/test/test/test/test/test//test/test/test/test/test/test/test//test/test/test/test/test/test/test//test/test/test/test/test/test/test//test/test/test/test/test/test/test//test/test/test/test/test/test/test/",
	} {
		i := makeBPFInfoWithBuf([]uint8(s))
		assert.NotEmpty(t, i.url(), fmt.Sprintf("-%s-", s))
		assert.NotEmpty(t, i.method(), fmt.Sprintf("-%s-", s))
		assert.True(t, strings.HasPrefix(i.url(), "/test"))
	}

	i := makeBPFInfoWithBuf([]uint8("GET "))
	assert.NotEmpty(t, i.method())
	assert.Empty(t, i.url())

	i = makeBPFInfoWithBuf([]uint8(""))
	assert.Empty(t, i.method())
	assert.Empty(t, i.url())

	i = makeBPFInfoWithBuf([]uint8("POST"))
	assert.Empty(t, i.method())
	assert.Empty(t, i.url())
}

func makeHTTPInfo(method, path, peer, host string, peerPort, hostPort uint32, status uint16, durationMs uint64) HTTPInfo {
	bpfInfo := BPFHTTPInfo{
		Type:            1,
		Status:          status,
		StartMonotimeNs: durationMs * 1000000,
		EndMonotimeNs:   durationMs * 2 * 1000000,
	}
	i := HTTPInfo{
		BPFHTTPInfo: bpfInfo,
		Method:      method,
		Peer:        peer,
		URL:         path,
		Host:        host,
	}

	i.ConnInfo.D_port = uint16(hostPort)
	i.ConnInfo.S_port = uint16(peerPort)

	return i
}

func assertMatchesInfo(t *testing.T, span *request.Span, method, path, peer, host string, hostPort int, status int, durationMs uint64) {
	assert.Equal(t, method, span.Method)
	assert.Equal(t, path, span.Path)
	assert.Equal(t, host, span.Host)
	assert.Equal(t, hostPort, span.HostPort)
	assert.Equal(t, peer, span.Peer)
	assert.Equal(t, status, span.Status)
	assert.Equal(t, int64(durationMs*1000000), span.End-span.Start)
	assert.Equal(t, int64(durationMs*1000000), span.End-span.RequestStart)
}

func makeBPFInfoWithBuf(buf []uint8) BPFHTTPInfo {
	bpfInfo := BPFHTTPInfo{}
	copy(bpfInfo.Buf[:], buf)

	return bpfInfo
}
