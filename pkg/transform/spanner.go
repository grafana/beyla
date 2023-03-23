package transform

import (
	"bytes"
	"net"
	"time"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"

	"github.com/gavv/monotime"
)

// HTTPRequestSpan contains the information being submitted as
type HTTPRequestSpan struct {
	Method   string
	Path     string
	Route    string
	Peer     string
	PeerPort int
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
	remoteAddrLen := bytes.IndexByte(trace.RemoteAddr[:], 0)
	if remoteAddrLen < 0 {
		remoteAddrLen = len(trace.RemoteAddr)
	}

	peer := ""

	if remoteAddrLen > 0 {
		remoteAddr := string(trace.RemoteAddr[:remoteAddrLen])
		ip, _, err := net.SplitHostPort(remoteAddr)
		// we ignore the peer port, it's not very useful for metrics and traces
		if err != nil {
			peer = remoteAddr
		} else {
			peer = ip
		}
	}

	return HTTPRequestSpan{
		Method: string(trace.Method[:methodLen]),
		Path:   string(trace.Path[:pathLen]),
		Peer:   peer,
		Start:  now.Add(-startDelta),
		End:    now.Add(-endDelta),
		Status: int(trace.Status),
	}
}
