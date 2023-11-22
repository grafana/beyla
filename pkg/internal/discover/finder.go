package discover

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/ebpf/goruntime"
	"github.com/grafana/beyla/pkg/internal/ebpf/gosql"
	"github.com/grafana/beyla/pkg/internal/ebpf/grpc"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpfltr"
	"github.com/grafana/beyla/pkg/internal/ebpf/nethttp"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// ProcessFinder pipeline architecture. It uses the Pipes library to instantiate and connect all the nodes.
type ProcessFinder struct {
	Watcher         `sendTo:"CriteriaMatcher"`
	CriteriaMatcher `sendTo:"ExecTyper"`
	ExecTyper       `sendTo:"ContainerDBUpdater"`
	// ContainerDBUpdater will be only enabled (non-nil value) if Kubernetes decoration is enabled
	*ContainerDBUpdater `forwardTo:"TraceAttacher"`
	TraceAttacher
}

func NewProcessFinder(ctx context.Context, cfg *pipe.Config, ctxInfo *global.ContextInfo) *ProcessFinder {
	var cntDB *ContainerDBUpdater
	if cfg.Attributes.Kubernetes.Enabled() {
		cntDB = &ContainerDBUpdater{DB: ctxInfo.K8sDatabase}
	}
	return &ProcessFinder{
		Watcher:            Watcher{Ctx: ctx, Cfg: cfg},
		CriteriaMatcher:    CriteriaMatcher{Cfg: cfg},
		ExecTyper:          ExecTyper{Cfg: cfg, Metrics: ctxInfo.Metrics},
		ContainerDBUpdater: cntDB,
		TraceAttacher: TraceAttacher{
			Cfg:               cfg,
			Ctx:               ctx,
			DiscoveredTracers: make(chan *ebpf.ProcessTracer),
			Metrics:           ctxInfo.Metrics,
		},
	}
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new discovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start(cfg *pipe.Config) (<-chan *ebpf.ProcessTracer, error) {
	gb := graph.NewBuilder(node.ChannelBufferLen(cfg.ChannelBufferLen))
	graph.RegisterStart(gb, WatcherProvider)
	graph.RegisterMiddle(gb, CriteriaMatcherProvider)
	graph.RegisterMiddle(gb, ExecTyperProvider)
	graph.RegisterMiddle(gb, ContainerDBUpdaterProvider)
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
		nethttp.New(&cfg.EBPF, metrics),
		&nethttp.GinTracer{Tracer: *nethttp.New(&cfg.EBPF, metrics)},
		grpc.New(&cfg.EBPF, metrics),
		goruntime.New(&cfg.EBPF, metrics),
		gosql.New(&cfg.EBPF, metrics),
	}
}

func newNonGoTracersGroup(cfg *pipe.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{httpfltr.New(cfg, metrics)}
}
