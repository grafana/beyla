package spanner

import (
	"bytes"
	"time"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"

	"github.com/gavv/monotime"
)

// HttpRequestSpan contains the information being submitted as
type HttpRequestSpan struct {
	Method string
	Path   string
	Status int
	Start  time.Time
	End    time.Time
}

func ConvertToSpan(in <-chan nethttp.HttpRequestTrace, out chan<- HttpRequestSpan) {
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

func (c *converter) convert(trace *nethttp.HttpRequestTrace) HttpRequestSpan {
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
	return HttpRequestSpan{
		Method: string(trace.Method[:methodLen]),
		Path:   string(trace.Path[:pathLen]),
		Start:  now.Add(-startDelta),
		End:    now.Add(-endDelta),
		Status: int(trace.Status),
	}
}
