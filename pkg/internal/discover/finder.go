package discover

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/generictracer"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/gotracer"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/gpuevent"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/httptracer"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/tctracer"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

type ProcessFinder struct {
	ctx         context.Context
	cfg         *beyla.Config
	ctxInfo     *global.ContextInfo
	tracesInput chan<- []request.Span
}

// nodesMap stores ProcessFinder pipeline architecture
type nodesMap struct {
	ProcessWatcher      pipe.Start[[]Event[processAttrs]]
	WatcherKubeEnricher pipe.Middle[[]Event[processAttrs], []Event[processAttrs]]
	CriteriaMatcher     pipe.Middle[[]Event[processAttrs], []Event[ProcessMatch]]
	ExecTyper           pipe.Middle[[]Event[ProcessMatch], []Event[ebpf.Instrumentable]]
	ContainerDBUpdater  pipe.Middle[[]Event[ebpf.Instrumentable], []Event[ebpf.Instrumentable]]
	TraceAttacher       pipe.Final[[]Event[ebpf.Instrumentable]]
}

func (pf *nodesMap) Connect() {
	pf.ProcessWatcher.SendTo(pf.WatcherKubeEnricher)
	pf.WatcherKubeEnricher.SendTo(pf.CriteriaMatcher)
	pf.CriteriaMatcher.SendTo(pf.ExecTyper)
	pf.ExecTyper.SendTo(pf.ContainerDBUpdater)
	pf.ContainerDBUpdater.SendTo(pf.TraceAttacher)
}

func processWatcher(pf *nodesMap) *pipe.Start[[]Event[processAttrs]] { return &pf.ProcessWatcher }
func ptrWatcherKubeEnricher(pf *nodesMap) *pipe.Middle[[]Event[processAttrs], []Event[processAttrs]] {
	return &pf.WatcherKubeEnricher
}
func criteriaMatcher(pf *nodesMap) *pipe.Middle[[]Event[processAttrs], []Event[ProcessMatch]] {
	return &pf.CriteriaMatcher
}
func execTyper(pf *nodesMap) *pipe.Middle[[]Event[ProcessMatch], []Event[ebpf.Instrumentable]] {
	return &pf.ExecTyper
}
func containerDBUpdater(pf *nodesMap) *pipe.Middle[[]Event[ebpf.Instrumentable], []Event[ebpf.Instrumentable]] {
	return &pf.ContainerDBUpdater
}
func traceAttacher(pf *nodesMap) *pipe.Final[[]Event[ebpf.Instrumentable]] { return &pf.TraceAttacher }

func NewProcessFinder(ctx context.Context, cfg *beyla.Config, ctxInfo *global.ContextInfo, tracesInput chan<- []request.Span) *ProcessFinder {
	return &ProcessFinder{ctx: ctx, cfg: cfg, ctxInfo: ctxInfo, tracesInput: tracesInput}
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new discovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start() (<-chan *ebpf.Instrumentable, <-chan *ebpf.Instrumentable, error) {

	discoveredTracers, deleteTracers := make(chan *ebpf.Instrumentable), make(chan *ebpf.Instrumentable)

	gb := pipe.NewBuilder(&nodesMap{}, pipe.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	pipe.AddStart(gb, processWatcher, ProcessWatcherFunc(pf.ctx, pf.cfg))
	pipe.AddMiddleProvider(gb, ptrWatcherKubeEnricher,
		WatcherKubeEnricherProvider(pf.ctx, pf.ctxInfo.K8sInformer))
	pipe.AddMiddleProvider(gb, criteriaMatcher, CriteriaMatcherProvider(pf.cfg))
	pipe.AddMiddleProvider(gb, execTyper, ExecTyperProvider(pf.cfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer))
	pipe.AddMiddleProvider(gb, containerDBUpdater, ContainerDBUpdaterProvider(pf.ctx, pf.ctxInfo.K8sInformer))
	pipe.AddFinalProvider(gb, traceAttacher, TraceAttacherProvider(&TraceAttacher{
		Cfg:                 pf.cfg,
		Ctx:                 pf.ctx,
		DiscoveredTracers:   discoveredTracers,
		DeleteTracers:       deleteTracers,
		Metrics:             pf.ctxInfo.Metrics,
		SpanSignalsShortcut: pf.tracesInput,
	}))
	pipeline, err := gb.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("can't instantiate discovery.ProcessFinder pipeline: %w", err)
	}
	pipeline.Start()
	return discoveredTracers, deleteTracers, nil
}

// auxiliary functions to instantiate the go and non-go tracers on diverse steps of the
// discovery pipeline

// the common tracer group should get loaded for any tracer group, only once
func newCommonTracersGroup(cfg *beyla.Config) []ebpf.Tracer {
	tracers := []ebpf.Tracer{}

	if cfg.EBPF.UseTCForL7CP {
		tracers = append(tracers, httptracer.New(cfg))
	} else if cfg.EBPF.ContextPropagationEnabled {
		tracers = append(tracers, tctracer.New(cfg))
	}

	return tracers
}

func newGoTracersGroup(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{gotracer.New(cfg, metrics)}
}

func newGenericTracersGroup(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	if cfg.EBPF.InstrumentGPU {
		return []ebpf.Tracer{generictracer.New(cfg, metrics), gpuevent.New(cfg, metrics)}
	}
	return []ebpf.Tracer{generictracer.New(cfg, metrics)}
}
