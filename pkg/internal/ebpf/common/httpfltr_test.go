package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

const bufSize = 256

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

	source, target := (*BPFConnInfo)(unsafe.Pointer(&event.ConnInfo)).reqHostInfo()

	assert.Equal(t, "192.168.0.1", source)
	assert.Equal(t, "8.8.8.8", target)

	event = BPFHTTPInfo{
		ConnInfo: bpfConnectionInfoT{
			S_addr: [16]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
			D_addr: [16]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8},
		},
	}

	source, target = (*BPFConnInfo)(unsafe.Pointer(&event.ConnInfo)).reqHostInfo()

	assert.Equal(t, "100::ffff:c0a8:1", source)
	assert.Equal(t, "100::ffff:808:808", target)

	event = BPFHTTPInfo{
		ConnInfo: bpfConnectionInfoT{},
	}

	source, target = (*BPFConnInfo)(unsafe.Pointer(&event.ConnInfo)).reqHostInfo()

	assert.Equal(t, "", source)
	assert.Equal(t, "", target)
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
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}

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

	result, _, err := ReadHTTPInfoIntoSpan(&ringbuf.Record{RawSample: buf.Bytes()}, &fltr)
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
		Service:      svc.Attrs{},
		Statement:    "http;",
	}
	assert.Equal(t, expected, result)
}

func TestToRequestTraceNoConnection(t *testing.T) {
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}

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

	result, _, err := ReadHTTPInfoIntoSpan(&ringbuf.Record{RawSample: buf.Bytes()}, &fltr)
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
		Service:      svc.Attrs{},
		Statement:    "http;localhost",
	}
	assert.Equal(t, expected, result)
}

func TestToRequestTrace_BadHost(t *testing.T) {
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}

	var record BPFHTTPInfo
	record.Type = 1
	record.StartMonotimeNs = 123456
	record.EndMonotimeNs = 789012
	record.Status = 200
	record.ConnInfo.D_port = 0
	record.ConnInfo.S_port = 0
	record.ConnInfo.S_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	record.ConnInfo.D_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8}
	copy(record.Buf[:], "GET /hello HTTP/1.1\r\nHost: example.c")

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &record)
	assert.NoError(t, err)

	result, _, err := ReadHTTPInfoIntoSpan(&ringbuf.Record{RawSample: buf.Bytes()}, &fltr)
	assert.NoError(t, err)

	expected := request.Span{
		Host:         "",
		Peer:         "",
		Path:         "/hello",
		Method:       "GET",
		Status:       200,
		Type:         request.EventTypeHTTP,
		RequestStart: 123456,
		Start:        123456,
		End:          789012,
		HostPort:     0,
		Service:      svc.Attrs{},
		Statement:    "http;example.c",
	}
	assert.Equal(t, expected, result)

	s, p := record.hostFromBuf()
	assert.Equal(t, "example.c", s)
	assert.Equal(t, -1, p)

	var record1 BPFHTTPInfo
	copy(record1.Buf[:], "GET /hello HTTP/1.1\r\nHost: example.c:23")

	s, p = record1.hostFromBuf()
	assert.Equal(t, s, "example.c")
	assert.Equal(t, p, 23)

	var record2 BPFHTTPInfo
	copy(record2.Buf[:], "GET /hello HTTP/1.1\r\nHost: ")

	s, p = record2.hostFromBuf()
	assert.Equal(t, s, "")
	assert.Equal(t, p, -1)

	var record3 BPFHTTPInfo
	copy(record3.Buf[:], "GET /hello HTTP/1.1\r\nHost")

	s, p = record3.hostFromBuf()
	assert.Equal(t, s, "")
	assert.Equal(t, p, -1)
}
