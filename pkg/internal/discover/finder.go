package discover

import (
	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/ebpf/goruntime"
	"github.com/grafana/beyla/pkg/internal/ebpf/grpc"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpfltr"
	"github.com/grafana/beyla/pkg/internal/ebpf/nethttp"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
)


type ProcessFinder struct {
	Watcher         `sendTo:"CriteriaMatcher"`
	CriteriaMatcher `sendTo:"ExecTyper"`
	ExecTyper       `sendTo:"TraceAttacher"`
	TraceAttacher
}

func newGoProgramsGroup(cfg *pipe.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	// Each program is an eBPF source: net/http, grpc...
	return []ebpf.Tracer{
		&nethttp.Tracer{Cfg: &cfg.EBPF, Metrics: metrics},
		&nethttp.GinTracer{Tracer: nethttp.Tracer{Cfg: &cfg.EBPF, Metrics: metrics}},
		&grpc.Tracer{Cfg: &cfg.EBPF, Metrics: metrics},
		&goruntime.Tracer{Cfg: &cfg.EBPF, Metrics: metrics},
	}
}

func newNonGoProgramsGroup(cfg *pipe.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{&httpfltr.Tracer{Cfg: cfg, Metrics: metrics}}
}
