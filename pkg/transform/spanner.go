package transform

import (
	"bytes"
	"net"
	"strconv"
	"time"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/ebpf/common"

	"github.com/gavv/monotime"
	"golang.org/x/exp/slog"
)

const EventTypeHTTP = 1
const EventTypeGRPC = 2
const EventTypeHTTPClient = 3
const EventTypeGRPCClient = 4

var log = slog.With("component", "goexec.spanner")

// HTTPRequestSpan contains the information being submitted by the following nodes in the graph.
// It enables confortable handling of data from Go.
type HTTPRequestSpan struct {
	Type          int
	ID            uint64
	Method        string
	Path          string
	Route         string
	Peer          string
	Host          string
	HostPort      int
	Status        int
	ContentLength int64
	RequestStart  time.Time
	Start         time.Time
	End           time.Time
}

func ConvertToSpan(in <-chan []ebpfcommon.HTTPRequestTrace, out chan<- []HTTPRequestSpan) {
	cnv := newConverter()
	for traces := range in {
		spans := make([]HTTPRequestSpan, 0, len(traces))
		for i := range traces {
			spans = append(spans, cnv.convert(&traces[i]))
		}
		out <- spans
	}
}

func (c *HTTPRequestSpan) Inside(parent *HTTPRequestSpan) bool {
	return c.Start.Compare(parent.RequestStart) >= 0 && c.End.Compare(parent.End) <= 0
}

func newConverter() converter {
	return converter{
		monoClock: monotime.Now,
		clock:     time.Now,
	}
}

type converter struct {
	clock     func() time.Time
	monoClock func() time.Duration
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

func (c *converter) convert(trace *ebpfcommon.HTTPRequestTrace) HTTPRequestSpan {
	now := time.Now()
	monoNow := c.monoClock()
	startDelta := monoNow - time.Duration(trace.StartMonotimeNs)
	endDelta := monoNow - time.Duration(trace.EndMonotimeNs)
	goStartDelta := monoNow - time.Duration(trace.GoStartMonotimeNs)

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

	switch trace.Type {
	case EventTypeHTTPClient, EventTypeHTTP:
		peer, _ = extractHostPort(trace.RemoteAddr[:])
		hostname, hostPort = extractHostPort(trace.Host[:])
	case EventTypeGRPC:
		hostPort = int(trace.HostPort)
		peer = extractIP(trace.RemoteAddr[:], int(trace.RemoteAddrLen))
		hostname = extractIP(trace.Host[:], int(trace.HostLen))
	case EventTypeGRPCClient:
		hostname, hostPort = extractHostPort(trace.Host[:])
	default:
		log.Warn("unknown trace type %d", trace.Type)
	}

	return HTTPRequestSpan{
		Type:          int(trace.Type),
		ID:            trace.Id,
		Method:        string(trace.Method[:methodLen]),
		Path:          string(trace.Path[:pathLen]),
		Peer:          peer,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: trace.ContentLength,
		RequestStart:  now.Add(-goStartDelta),
		Start:         now.Add(-startDelta),
		End:           now.Add(-endDelta),
		Status:        int(trace.Status),
	}
}
