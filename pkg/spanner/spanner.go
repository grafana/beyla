package spanner

import (
	"time"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"

	"github.com/gavv/monotime"
)

// values according to net/tcp_states.h
const (
	tcpEstablished = 1
	tcpClose       = 7
)

type HttpRequestSpan struct {
	Method string
	Path   string
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

	return HttpRequestSpan{
		Method: string(trace.Method[:]),
		Path:   string(trace.Path[:]),
		Start:  now.Add(-startDelta),
		End:    now.Add(-endDelta),
	}
}
