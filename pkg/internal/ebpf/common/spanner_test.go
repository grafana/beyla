package ebpfcommon

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/request"
)

func tocstr(s string) []byte {
	b := []byte(s)
	return append(b, 0)
}

func makeHTTPRequestTrace(method, path string, status uint16, durationMs uint64) HTTPRequestTrace {
	m := [7]uint8{}
	copy(m[:], tocstr(method))
	p := [100]uint8{}
	copy(p[:], tocstr(path))

	return HTTPRequestTrace{
		Type:              1, // transform.EventTypeHTTP
		Method:            m,
		Path:              p,
		Status:            status,
		GoStartMonotimeNs: 0,
		StartMonotimeNs:   durationMs * 1000000,
		EndMonotimeNs:     durationMs * 2 * 1000000,
	}
}

func makeGRPCRequestTrace(path string, status uint16, durationMs uint64) HTTPRequestTrace {
	p := [100]uint8{}
	copy(p[:], tocstr(path))

	return HTTPRequestTrace{
		Type:              2, // transform.EventTypeGRPC
		Path:              p,
		Status:            status,
		GoStartMonotimeNs: 0,
		StartMonotimeNs:   durationMs * 1000000,
		EndMonotimeNs:     durationMs * 2 * 1000000,
	}
}

func assertMatches(t *testing.T, span *request.Span, method, path string, status int, durationMs uint64) {
	assert.Equal(t, method, span.Method)
	assert.Equal(t, path, span.Path)
	assert.Equal(t, status, span.Status)
	assert.Equal(t, int64(durationMs*1000000), int64(span.End-span.Start))
	assert.Equal(t, int64(durationMs*1000000), int64(span.Start-span.RequestStart))
}

func TestRequestTraceParsing(t *testing.T) {
	t.Run("Test basic parsing", func(t *testing.T) {
		tr := makeHTTPRequestTrace("POST", "/users", 200, 5)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "POST", "/users", 200, 5)
	})

	t.Run("Test with empty path and missing peer host", func(t *testing.T) {
		tr := makeHTTPRequestTrace("GET", "", 403, 6)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "GET", "", 403, 6)
	})

	t.Run("Test with missing peer port", func(t *testing.T) {
		tr := makeHTTPRequestTrace("GET", "/posts/1/1", 500, 1)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "GET", "/posts/1/1", 500, 1)
	})

	t.Run("Test with invalid peer port", func(t *testing.T) {
		tr := makeHTTPRequestTrace("GET", "/posts/1/1", 500, 1)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "GET", "/posts/1/1", 500, 1)
	})

	t.Run("Test with GRPC request", func(t *testing.T) {
		tr := makeGRPCRequestTrace("/posts/1/1", 2, 1)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "", "/posts/1/1", 2, 1)
	})
}

func makeSpanWithTimings(goStart, start, end uint64) request.Span {
	tr := HTTPRequestTrace{
		Type:              1,
		Path:              [100]uint8{},
		Status:            0,
		GoStartMonotimeNs: goStart,
		StartMonotimeNs:   start,
		EndMonotimeNs:     end,
	}

	return HTTPRequestTraceToSpan(&tr)
}

func TestSpanNesting(t *testing.T) {
	a := makeSpanWithTimings(10000, 20000, 30000)
	b := makeSpanWithTimings(10000, 30000, 40000)
	assert.True(t, (&a).Inside(&b))
	a = makeSpanWithTimings(10000, 20000, 30000)
	b = makeSpanWithTimings(10000, 30000, 30000)
	assert.True(t, (&a).Inside(&b))
	a = makeSpanWithTimings(11000, 11000, 30000)
	b = makeSpanWithTimings(10000, 30000, 30000)
	assert.True(t, (&a).Inside(&b))
	a = makeSpanWithTimings(11000, 11000, 30001)
	b = makeSpanWithTimings(10000, 30000, 30000)
	assert.False(t, (&a).Inside(&b))
	a = makeSpanWithTimings(9999, 11000, 19999)
	b = makeSpanWithTimings(10000, 30000, 30000)
	assert.False(t, (&a).Inside(&b))
}

func Test_EmptyHostInfo(t *testing.T) {
	tr := HTTPRequestTrace{}
	src, dest := (*BPFConnInfo)(unsafe.Pointer(&tr.Conn)).reqHostInfo()

	assert.Equal(t, src, "")
	assert.Equal(t, dest, "")
}
