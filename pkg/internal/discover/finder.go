package discover

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/ebpf/goredis"
	"github.com/grafana/beyla/pkg/internal/ebpf/goruntime"
	"github.com/grafana/beyla/pkg/internal/ebpf/grpc"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpfltr"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpssl"
	"github.com/grafana/beyla/pkg/internal/ebpf/kafkago"
	"github.com/grafana/beyla/pkg/internal/ebpf/nethttp"
	"github.com/grafana/beyla/pkg/internal/ebpf/nodejs"
	"github.com/grafana/beyla/pkg/internal/ebpf/sarama"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
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
	ExecTyper           pipe.Middle[[]Event[ProcessMatch], []Event[Instrumentable]]
	ContainerDBUpdater  pipe.Middle[[]Event[Instrumentable], []Event[Instrumentable]]
	TraceAttacher       pipe.Final[[]Event[Instrumentable]]
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
func execTyper(pf *nodesMap) *pipe.Middle[[]Event[ProcessMatch], []Event[Instrumentable]] {
	return &pf.ExecTyper
}
func containerDBUpdater(pf *nodesMap) *pipe.Middle[[]Event[Instrumentable], []Event[Instrumentable]] {
	return &pf.ContainerDBUpdater
}
func traceAttacher(pf *nodesMap) *pipe.Final[[]Event[Instrumentable]] { return &pf.TraceAttacher }

func NewProcessFinder(ctx context.Context, cfg *beyla.Config, ctxInfo *global.ContextInfo, tracesInput chan<- []request.Span) *ProcessFinder {
	return &ProcessFinder{ctx: ctx, cfg: cfg, ctxInfo: ctxInfo, tracesInput: tracesInput}
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new discovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start() (<-chan *ebpf.ProcessTracer, <-chan *Instrumentable, error) {

	discoveredTracers, deleteTracers := make(chan *ebpf.ProcessTracer), make(chan *Instrumentable)

	gb := pipe.NewBuilder(&nodesMap{}, pipe.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	pipe.AddStart(gb, processWatcher, ProcessWatcherFunc(pf.ctx, pf.cfg))
	pipe.AddMiddleProvider(gb, ptrWatcherKubeEnricher,
		WatcherKubeEnricherProvider(pf.ctx, pf.ctxInfo.K8sInformer))
	pipe.AddMiddleProvider(gb, criteriaMatcher, CriteriaMatcherProvider(pf.cfg))
	pipe.AddMiddleProvider(gb, execTyper, ExecTyperProvider(pf.cfg, pf.ctxInfo.Metrics))
	pipe.AddMiddleProvider(gb, containerDBUpdater,
		ContainerDBUpdaterProvider(pf.ctxInfo.K8sInformer.IsKubeEnabled(), pf.ctxInfo.AppO11y.K8sDatabase))
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

func newGoTracersGroup(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	// Each program is an eBPF source: net/http, grpc...
	return []ebpf.Tracer{
		nethttp.New(cfg, metrics),
		grpc.New(cfg, metrics),
		goruntime.New(cfg, metrics),
		sarama.New(cfg, metrics),
		&sarama.ShopifyKafkaTracer{Tracer: *sarama.New(cfg, metrics)},
		goredis.New(cfg, metrics),
		kafkago.New(cfg, metrics),
	}
}

func newNonGoTracersGroup(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{httpfltr.New(cfg, metrics), httpssl.New(cfg, metrics)}
}

func newNonGoTracersGroupUProbes(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{httpssl.New(cfg, metrics)}
}

func newNodeJSTracersGroup(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{nodejs.New(cfg, metrics)}
}
