package transform

import (
	"bytes"
	"net"
	"strconv"
	"time"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf/nethttp"

	"github.com/gavv/monotime"
	"golang.org/x/exp/slog"
)

const EventTypeHTTP = 1
const EventTypeGRPC = 2

var log = slog.With("component", "goexec.spanner")

// HTTPRequestSpan contains the information being submitted as
type HTTPRequestSpan struct {
	Method   string
	Path     string
	Route    string
	Peer     string
	Host     string
	HostPort int
	Status   int
	Start    time.Time
	End      time.Time
}

func ConvertToSpan(in <-chan nethttp.HTTPRequestTrace, out chan<- HTTPRequestSpan) {
	cnv := newConverter()
	for trace := range in {
		out <- cnv.convert(&trace)
	}
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

func (c *converter) convert(trace *nethttp.HTTPRequestTrace) HTTPRequestSpan {
	now := time.Now()
	monoNow := c.monoClock()
	startDelta := monoNow - time.Duration(trace.StartMonotimeNs)
	endDelta := monoNow - time.Duration(trace.EndMonotimeNs)

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
	case EventTypeHTTP:
		peer, _ = extractHostPort(trace.RemoteAddr[:])
		hostname, hostPort = extractHostPort(trace.Host[:])
	case EventTypeGRPC:
		hostPort = int(trace.HostPort)
		peer = extractIP(trace.RemoteAddr[:], int(trace.RemoteAddrLen))
		hostname = extractIP(trace.Host[:], int(trace.HostLen))
	default:
		log.Warn("unknown trace type %d", trace.Type)
	}

	return HTTPRequestSpan{
		Method:   string(trace.Method[:methodLen]),
		Path:     string(trace.Path[:pathLen]),
		Peer:     peer,
		Host:     hostname,
		HostPort: hostPort,
		Start:    now.Add(-startDelta),
		End:      now.Add(-endDelta),
		Status:   int(trace.Status),
	}
}
