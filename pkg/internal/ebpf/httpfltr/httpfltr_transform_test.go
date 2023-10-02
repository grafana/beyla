package httpfltr

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/request"
)

func TestHTTPInfoParsing(t *testing.T) {
	t.Run("Test basic parsing", func(t *testing.T) {
		tr := makeHTTPInfo("POST", "/users", "127.0.0.1", "127.0.0.2", "curl", 12345, 8080, 200, 5)
		s := httpInfoToSpan(&tr)
		assertMatchesInfo(t, &s, "POST", "/users", "127.0.0.1", "127.0.0.2", "curl", 8080, 200, 5)
	})

	t.Run("Test empty URL", func(t *testing.T) {
		tr := makeHTTPInfo("POST", "", "127.0.0.1", "127.0.0.2", "curl", 12345, 8080, 200, 5)
		s := httpInfoToSpan(&tr)
		assertMatchesInfo(t, &s, "POST", "", "127.0.0.1", "127.0.0.2", "curl", 8080, 200, 5)
	})

	t.Run("Test parsing with URL parameters", func(t *testing.T) {
		tr := makeHTTPInfo("POST", "/users?query=1234", "127.0.0.1", "127.0.0.2", "curl", 12345, 8080, 200, 5)
		s := httpInfoToSpan(&tr)
		assertMatchesInfo(t, &s, "POST", "/users", "127.0.0.1", "127.0.0.2", "curl", 8080, 200, 5)
	})
}

func makeHTTPInfo(method, path, peer, host, comm string, peerPort, hostPort uint32, status uint16, durationMs uint64) HTTPInfo {
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
		Comm:        comm,
	}

	i.ConnInfo.D_port = uint16(hostPort)
	i.ConnInfo.S_port = uint16(peerPort)

	return i
}

func assertMatchesInfo(t *testing.T, span *request.Span, method, path, peer, host, comm string, hostPort int, status int, durationMs uint64) {
	assert.Equal(t, method, span.Method)
	assert.Equal(t, path, span.Path)
	assert.Equal(t, host, span.Host)
	assert.Equal(t, hostPort, span.HostPort)
	assert.Equal(t, peer, span.Peer)
	assert.Equal(t, status, span.Status)
	assert.Equal(t, comm, span.ServiceID.Name)
	assert.Equal(t, int64(durationMs*1000000), int64(span.End-span.Start))
	assert.Equal(t, int64(durationMs*1000000), int64(span.End-span.RequestStart))
}
