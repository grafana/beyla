package httpfltr

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/request"
)

const bufSize = 160

func TestURL(t *testing.T) {
	event := BPFHTTPInfo{
		Buf: [bufSize]byte{'G', 'E', 'T', ' ', '/', 'p', 'a', 't', 'h', '?', 'q', 'u', 'e', 'r', 'y', '=', '1', '2', '3', '4', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1'},
	}
	assert.Equal(t, "/path?query=1234", event.url())
	event = BPFHTTPInfo{}
	assert.Equal(t, "", event.url())
}

func TestMethod(t *testing.T) {
	event := BPFHTTPInfo{
		Buf: [bufSize]byte{'G', 'E', 'T', ' ', '/', 'p', 'a', 't', 'h', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1'},
	}

	assert.Equal(t, "GET", event.method())
	event = BPFHTTPInfo{}
	assert.Equal(t, "", event.method())
}

func TestHostInfo(t *testing.T) {
	event := BPFHTTPInfo{
		ConnInfo: bpfConnectionInfoT{
			S_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
			D_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8},
		},
	}

	source, target := event.hostInfo()

	assert.Equal(t, "192.168.0.1", source)
	assert.Equal(t, "8.8.8.8", target)

	event = BPFHTTPInfo{
		ConnInfo: bpfConnectionInfoT{
			S_addr: [16]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
			D_addr: [16]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8},
		},
	}

	source, target = event.hostInfo()

	assert.Equal(t, "100::ffff:c0a8:1", source)
	assert.Equal(t, "100::ffff:808:808", target)

	event = BPFHTTPInfo{
		ConnInfo: bpfConnectionInfoT{},
	}

	source, target = event.hostInfo()

	assert.Equal(t, "::", source)
	assert.Equal(t, "::", target)
}

func TestCstr(t *testing.T) {
	testCases := []struct {
		input    []uint8
		expected string
	}{
		{[]uint8{72, 101, 108, 108, 111, 0}, "Hello"},
		{[]uint8{87, 111, 114, 108, 100, 0}, "World"},
		{[]uint8{72, 101, 108, 108, 111}, "Hello"},
		{[]uint8{87, 111, 114, 108, 100}, "World"},
		{[]uint8{}, ""},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.expected, cstr(tc.input))
	}
}

func TestToRequestTrace(t *testing.T) {
	var record BPFHTTPInfo
	record.Type = 1
	record.StartMonotimeNs = 123456
	record.EndMonotimeNs = 789012
	record.Status = 200
	record.ConnInfo.D_port = 1
	record.ConnInfo.S_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	record.ConnInfo.D_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8}
	copy(record.Buf[:], "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n")

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &record)
	assert.NoError(t, err)

	tracer := Tracer{Cfg: &pipe.Config{}}
	result, _, err := tracer.readHTTPInfoIntoSpan(&ringbuf.Record{RawSample: buf.Bytes()})
	assert.NoError(t, err)

	expected := request.Span{
		Host:         "8.8.8.8",
		Peer:         "192.168.0.1",
		Path:         "/hello",
		Method:       "GET",
		Status:       200,
		Type:         request.EventTypeHTTP,
		RequestStart: 123456,
		Start:        123456,
		End:          789012,
		HostPort:     1,
	}
	assert.Equal(t, expected, result)
}

func TestToRequestTraceNoConnection(t *testing.T) {
	var record BPFHTTPInfo
	record.Type = 1
	record.StartMonotimeNs = 123456
	record.EndMonotimeNs = 789012
	record.Status = 200
	record.ConnInfo.S_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	record.ConnInfo.D_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8}
	copy(record.Buf[:], "GET /hello HTTP/1.1\r\nHost: localhost:7033\r\n\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\n")

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &record)
	assert.NoError(t, err)

	tracer := Tracer{Cfg: &pipe.Config{}}
	result, _, err := tracer.readHTTPInfoIntoSpan(&ringbuf.Record{RawSample: buf.Bytes()})
	assert.NoError(t, err)

	// change the expected port just before testing
	expected := request.Span{
		Host:         "localhost",
		Peer:         "",
		Path:         "/hello",
		Method:       "GET",
		Type:         request.EventTypeHTTP,
		Start:        123456,
		RequestStart: 123456,
		End:          789012,
		Status:       200,
		HostPort:     7033,
	}
	assert.Equal(t, expected, result)
}

func TestExtractTraceParent(t *testing.T) {
	tracer := Tracer{Cfg: &pipe.Config{}}

	// normal formulated request
	assert.Equal(t, "ABBA", tracer.extractTraceParent([]byte(
		"POST /smoke HTTP/1.1\r\n"+
			"Host: localhost:3030\r\n"+
			"User-Agent: curl/7.81.0\r\n"+
			"Accept: */*\r\n"+
			"Content-Type:application/json\r\n"+
			"TraceParent: ABBA\r\n"+
			"Content-Length: 33\r\n"+
			"\r\n"+
			"{\"name\": \"Joe\", \"number\": 123}")))

	// normal formulated request, weird casing
	assert.Equal(t, "AbbA", tracer.extractTraceParent([]byte(
		"POST /smoke HTTP/1.1\r\n"+
			"Host: localhost:3030\r\n"+
			"User-Agent: curl/7.81.0\r\n"+
			"Accept: */*\r\n"+
			"Content-Type:application/json\r\n"+
			"TrAcEpArEnT: AbbA\r\n"+
			"Content-Length: 33\r\n"+
			"\r\n"+
			"{\"name\": \"Joe\", \"number\": 123}")))

	// we only look up to the end of the headers section
	assert.Equal(t, "", tracer.extractTraceParent([]byte(
		"POST /smoke HTTP/1.1\r\n"+
			"Host: localhost:3030\r\n"+
			"User-Agent: curl/7.81.0\r\n"+
			"Accept: */*\r\n"+
			"Content-Type:application/json\r\n"+
			"Content-Length: 33\r\n"+
			"\r\n"+
			"{\"name\": \"Joe\", \"number\": 123, \"Traceparent\": \"ABBA\"}")))

	// we must find the end of headers in the buffer, if it's not there we do nothing
	assert.Equal(t, "", tracer.extractTraceParent([]byte(
		"POST /smoke HTTP/1.1\r\n"+
			"Host: localhost:3030\r\n"+
			"User-Agent: curl/7.81.0\r\n"+
			"Accept: */*\r\n"+
			"Content-Type:application/json\r\n"+
			"Content-Length: 33\r\n"+
			"{\"name\": \"Joe\", \"number\": 123, \"Traceparent\": \"ABBA\"\r\n}")))

	// we find the traceparent in body-less requests
	assert.Equal(t, "ABBA", tracer.extractTraceParent([]byte(
		"POST /smoke HTTP/1.1\r\n"+
			"Host: localhost:3030\r\n"+
			"User-Agent: curl/7.81.0\r\n"+
			"Accept: */*\r\n"+
			"Content-Type:application/json\r\n"+
			"TraceParent: ABBA\r\n"+
			"Content-Length: 33\r\n\r\n")))

	// empty buffer
	assert.Equal(t, "", tracer.extractTraceParent([]byte("")))

	// we find the traceparent but it's empty
	assert.Equal(t, "", tracer.extractTraceParent([]byte(
		"POST /smoke HTTP/1.1\r\n"+
			"Host: localhost:3030\r\n"+
			"User-Agent: curl/7.81.0\r\n"+
			"Accept: */*\r\n"+
			"Content-Type:application/json\r\n"+
			"TraceParent: \r\n"+
			"Content-Length: 33\r\n\r\n")))

	// Cut off
	assert.Equal(t, "", tracer.extractTraceParent([]byte(
		"POST /smoke HTTP/1.1\r\n"+
			"Host: localhost:3030\r\n"+
			"User-Agent: curl/7.81.0\r\n"+
			"Accept: */*\r\n"+
			"Content-Type:application/json\r\n"+
			"TraceParent: ")))
	// Differently Cut off
	assert.Equal(t, "", tracer.extractTraceParent([]byte(
		"POST /smoke HTTP/1.1\r\n"+
			"Host: localhost:3030\r\n"+
			"User-Agent: curl/7.81.0\r\n"+
			"Accept: */*\r\n"+
			"Content-Type:application/json\r\n"+
			"TraceParent: \r\n\r\n")))
}
