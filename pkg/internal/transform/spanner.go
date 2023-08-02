package transform

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gavv/monotime"
	"golang.org/x/exp/slog"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf/common"
	httpfltr "github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf/httpfltr"
)

type EventType int

const (
	EventTypeHTTP EventType = iota + 1
	EventTypeGRPC
	EventTypeHTTPClient
	EventTypeGRPCClient
)

var log = slog.With("component", "goexec.spanner")

type converter struct {
	clock     func() time.Time
	monoClock func() time.Duration
}

var clocks = converter{monoClock: monotime.Now, clock: time.Now}

// HTTPRequestSpan contains the information being submitted by the following nodes in the graph.
// It enables confortable handling of data from Go.
type HTTPRequestSpan struct {
	Type          EventType
	ID            uint64
	Method        string
	Path          string
	Route         string
	Peer          string
	Host          string
	HostPort      int
	Status        int
	ContentLength int64
	RequestStart  int64
	Start         int64
	End           int64
	ServiceName   string
	// Metadata can be composed from multiple maps to allow data sharing
	Metadata      []map[string]string
}

func ConvertToSpan(in <-chan []any, out chan<- []HTTPRequestSpan) {
	for traces := range in {
		spans := make([]HTTPRequestSpan, 0, len(traces))
		for i := range traces {
			v := traces[i]

			switch t := v.(type) {
			case ebpfcommon.HTTPRequestTrace:
				httpTrace := t
				spans = append(spans, convertFromHTTPTrace(&httpTrace))
			case httpfltr.HTTPInfo:
				info := t
				spans = append(spans, convertFromHTTPInfo(&info))
			}
		}
		out <- spans
	}
}

func extractHostPort(b []uint8) (string, int) {
	addrLen := bytes.IndexByte(b, 0)
	if addrLen < 0 {
		addrLen = len(b)
	}

	peer := ""
	peerPort := 0

	if addrLen > 0 {
		addr := string(b[:addrLen])
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			peer = addr
		} else {
			peer = ip
			peerPort, _ = strconv.Atoi(port)
		}
	}

	return peer, peerPort
}

func extractIP(b []uint8, size int) string {
	if size > len(b) {
		size = len(b)
	}
	return net.IP(b[:size]).String()
}

func (s *HTTPRequestSpan) Inside(parent *HTTPRequestSpan) bool {
	return s.RequestStart >= parent.RequestStart && s.End <= parent.End
}

type Timings struct {
	RequestStart time.Time
	Start        time.Time
	End          time.Time
}

func (s *HTTPRequestSpan) Timings() Timings {
	now := clocks.clock()
	monoNow := clocks.monoClock()
	startDelta := monoNow - time.Duration(s.Start)
	endDelta := monoNow - time.Duration(s.End)
	goStartDelta := monoNow - time.Duration(s.RequestStart)

	return Timings{
		RequestStart: now.Add(-goStartDelta),
		Start:        now.Add(-startDelta),
		End:          now.Add(-endDelta),
	}
}

func convertFromHTTPTrace(trace *ebpfcommon.HTTPRequestTrace) HTTPRequestSpan {
	// From C, assuming 0-ended strings
	methodLen := bytes.IndexByte(trace.Method[:], 0)
	if methodLen < 0 {
		methodLen = len(trace.Method)
	}
	pathLen := bytes.IndexByte(trace.Path[:], 0)
	if pathLen < 0 {
		pathLen = len(trace.Path)
	}

	peer := ""
	hostname := ""
	hostPort := 0

	switch EventType(trace.Type) {
	case EventTypeHTTPClient, EventTypeHTTP:
		peer, _ = extractHostPort(trace.RemoteAddr[:])
		hostname, hostPort = extractHostPort(trace.Host[:])
	case EventTypeGRPC:
		hostPort = int(trace.HostPort)
		peer = extractIP(trace.RemoteAddr[:], int(trace.RemoteAddrLen))
		hostname = extractIP(trace.Host[:], int(trace.HostLen))
	case EventTypeGRPCClient:
		hostname, hostPort = extractHostPort(trace.Host[:])
		peer = hostname
	default:
		log.Warn("unknown trace type %d", trace.Type)
	}

	return HTTPRequestSpan{
		Type:          EventType(trace.Type),
		ID:            trace.Id,
		Method:        string(trace.Method[:methodLen]),
		Path:          string(trace.Path[:pathLen]),
		Peer:          peer,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: trace.ContentLength,
		RequestStart:  int64(trace.GoStartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        int(trace.Status),
	}
}

func removeQuery(url string) string {
	idx := strings.IndexByte(url, '?')
	if idx > 0 {
		return url[:idx]
	}
	return url
}

func convertFromHTTPInfo(info *httpfltr.HTTPInfo) HTTPRequestSpan {
	return HTTPRequestSpan{
		Type:          EventType(info.Type),
		ID:            0,
		Method:        info.Method,
		Path:          removeQuery(info.URL),
		Peer:          info.Peer,
		Host:          info.Host,
		HostPort:      int(info.ConnInfo.D_port),
		ContentLength: int64(info.Len),
		RequestStart:  int64(info.StartMonotimeNs),
		Start:         int64(info.StartMonotimeNs),
		End:           int64(info.EndMonotimeNs),
		Status:        int(info.Status),
		ServiceName:   info.Comm,
	}
}
