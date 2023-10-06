package discover

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pkg/graph"

	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/ebpf/goruntime"
	"github.com/grafana/beyla/pkg/internal/ebpf/grpc"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpfltr"
	"github.com/grafana/beyla/pkg/internal/ebpf/nethttp"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
)

// ProcessFinder pipeline architecture. It uses the Pipes library to instantiate and connect all eht nodes.
type ProcessFinder struct {
	Watcher         `sendTo:"CriteriaMatcher"`
	CriteriaMatcher `sendTo:"ExecTyper"`
	ExecTyper       `sendTo:"TraceAttacher"`
	TraceAttacher
}

func NewProcessFinder(ctx context.Context, cfg *pipe.Config, metrics imetrics.Reporter) *ProcessFinder {
	return &ProcessFinder{
		Watcher:         Watcher{Ctx: ctx, PollInterval: cfg.Discovery.PollInterval},
		CriteriaMatcher: CriteriaMatcher{Cfg: cfg},
		ExecTyper:       ExecTyper{Cfg: cfg, Metrics: metrics},
		TraceAttacher: TraceAttacher{
			Cfg:               cfg,
			Ctx:               ctx,
			DiscoveredTracers: make(chan *ebpf.ProcessTracer),
			Metrics:           metrics,
		},
	}
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new discovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start() (<-chan *ebpf.ProcessTracer, error) {
	gb := graph.NewBuilder()
	graph.RegisterStart(gb, WatcherProvider)
	graph.RegisterMiddle(gb, CriteriaMatcherProvider)
	graph.RegisterMiddle(gb, ExecTyperProvider)
	graph.RegisterTerminal(gb, TraceAttacherProvider)
	pipeline, err := gb.Build(pf)
	if err != nil {
		return nil, fmt.Errorf("can't instantiate discovery.ProcessFinder pipeline: %w", err)
	}
	go pipeline.Run()
	return pf.DiscoveredTracers, nil
}

// auxiliary functions to instantiate the go and non-go tracers on diverse steps of the
// discovery pipeline

func newGoTracersGroup(cfg *pipe.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	// Each program is an eBPF source: net/http, grpc...
	return []ebpf.Tracer{
		&nethttp.Tracer{Cfg: &cfg.EBPF, Metrics: metrics},
		&nethttp.GinTracer{Tracer: nethttp.Tracer{Cfg: &cfg.EBPF, Metrics: metrics}},
		&grpc.Tracer{Cfg: &cfg.EBPF, Metrics: metrics},
		&goruntime.Tracer{Cfg: &cfg.EBPF, Metrics: metrics},
	}
}

func newNonGoTracersGroup(cfg *pipe.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{&httpfltr.Tracer{Cfg: cfg, Metrics: metrics}}
}
