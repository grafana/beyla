package discover

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/ebpf/goruntime"
	"github.com/grafana/beyla/pkg/internal/ebpf/grpc"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpfltr"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpssl"
	"github.com/grafana/beyla/pkg/internal/ebpf/nethttp"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// ProcessFinder pipeline architecture. It uses the Pipes library to instantiate and connect all the nodes.
// Nodes tagged as "forwardTo" are optional nodes that might not be instantiated. In that case, any
// information directed to them will be automatically forwarded to the next pipeline stage.
// For example WatcherKubeEnricher and ContainerDBUpdater will be only enabled
// (non-nil values) if Kubernetes decoration is enabled
type ProcessFinder struct {
	ProcessWatcher       `sendTo:"WatcherKubeEnricher"`
	*WatcherKubeEnricher `forwardTo:"CriteriaMatcher"`
	CriteriaMatcher      `sendTo:"ExecTyper"`
	ExecTyper            `sendTo:"ContainerDBUpdater"`
	*ContainerDBUpdater  `forwardTo:"TraceAttacher"`
	TraceAttacher
}

func NewProcessFinder(ctx context.Context, cfg *beyla.Config, ctxInfo *global.ContextInfo) *ProcessFinder {
	processFinder := ProcessFinder{
		ProcessWatcher:  ProcessWatcher{Ctx: ctx, Cfg: cfg},
		CriteriaMatcher: CriteriaMatcher{Cfg: cfg},
		ExecTyper:       ExecTyper{Cfg: cfg, Metrics: ctxInfo.Metrics},
		TraceAttacher: TraceAttacher{
			Cfg:               cfg,
			Ctx:               ctx,
			DiscoveredTracers: make(chan *ebpf.ProcessTracer),
			DeleteTracers:     make(chan *Instrumentable),
			Metrics:           ctxInfo.Metrics,
		},
	}
	if ctxInfo.K8sEnabled {
		processFinder.ContainerDBUpdater = &ContainerDBUpdater{DB: ctxInfo.AppO11y.K8sDatabase}
		processFinder.WatcherKubeEnricher = &WatcherKubeEnricher{Informer: ctxInfo.AppO11y.K8sInformer}
	}
	return &processFinder
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new discovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start(cfg *beyla.Config) (<-chan *ebpf.ProcessTracer, <-chan *Instrumentable, error) {
	gb := graph.NewBuilder(node.ChannelBufferLen(cfg.ChannelBufferLen))
	graph.RegisterStart(gb, ProcessWatcherProvider)
	graph.RegisterMiddle(gb, WatcherKubeEnricherProvider)
	graph.RegisterMiddle(gb, CriteriaMatcherProvider)
	graph.RegisterMiddle(gb, ExecTyperProvider)
	graph.RegisterMiddle(gb, ContainerDBUpdaterProvider)
	graph.RegisterTerminal(gb, TraceAttacherProvider)
	pipeline, err := gb.Build(pf)
	if err != nil {
		return nil, nil, fmt.Errorf("can't instantiate discovery.ProcessFinder pipeline: %w", err)
	}
	go pipeline.Run()
	return pf.DiscoveredTracers, pf.DeleteTracers, nil
}

// auxiliary functions to instantiate the go and non-go tracers on diverse steps of the
// discovery pipeline

func newGoTracersGroup(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	// Each program is an eBPF source: net/http, grpc...
	return []ebpf.Tracer{
		nethttp.New(cfg, metrics),
		&nethttp.GinTracer{Tracer: *nethttp.New(cfg, metrics)},
		grpc.New(cfg, metrics),
		goruntime.New(cfg, metrics),
	}
}

func newNonGoTracersGroup(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{httpfltr.New(cfg, metrics), httpssl.New(cfg, metrics)}
}

func newNonGoTracersGroupUProbes(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{httpssl.New(cfg, metrics)}
}
