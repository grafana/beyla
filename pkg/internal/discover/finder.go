package discover

import (
	"context"
	"fmt"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf"
	ebpfcommon "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/common"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/generictracer"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/gotracer"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/gpuevent"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/tctracer"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/tpinjector"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/config"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/export/prom"
)

type ProcessFinder struct {
	cfg              *beyla.Config
	ctxInfo          *global.ContextInfo
	tracesInput      *msg.Queue[[]request.Span]
	ebpfEventContext *ebpfcommon.EBPFEventContext
}

func NewProcessFinder(
	cfg *beyla.Config,
	ctxInfo *global.ContextInfo,
	tracesInput *msg.Queue[[]request.Span],
	ebpfEventContext *ebpfcommon.EBPFEventContext) *ProcessFinder {
	return &ProcessFinder{cfg: cfg, ctxInfo: ctxInfo, tracesInput: tracesInput, ebpfEventContext: ebpfEventContext}
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new discovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start(ctx context.Context) (<-chan Event[*ebpf.Instrumentable], error) {

	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))

	swi := swarm.Instancer{}
	processEvents := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(swarm.DirectInstance(ProcessWatcherFunc(pf.cfg, pf.ebpfEventContext, processEvents)))

	kubeEnrichedEvents := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(WatcherKubeEnricherProvider(pf.ctxInfo.K8sInformer, processEvents, kubeEnrichedEvents))
	pf.connectSurveySubPipeline(&swi, kubeEnrichedEvents)

	criteriaFilteredEvents := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(CriteriaMatcherProvider(pf.cfg, kubeEnrichedEvents, criteriaFilteredEvents))

	executableTypes := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(ExecTyperProvider(pf.cfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer, criteriaFilteredEvents, executableTypes))

	// we could subscribe ContainerDBUpdater directly to the executableTypes queue and not providing any output channel
	// but forcing the output by the executableTypesReplica channel only after the Container DB has been updated
	// prevents race conditions in later stages of the pipeline
	storedExecutableTypes := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(ContainerDBUpdaterProvider(pf.ctxInfo.K8sInformer, executableTypes, storedExecutableTypes))

	swi.Add(TraceAttacherProvider(&TraceAttacher{
		Cfg:                  pf.cfg,
		OutputTracerEvents:   tracerEvents,
		Metrics:              pf.ctxInfo.Metrics,
		SpanSignalsShortcut:  pf.tracesInput,
		InputInstrumentables: storedExecutableTypes,
		ebpfEventContext:     pf.ebpfEventContext,
	}))

	pipeline, err := swi.Instance(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't instantiate discovery.ProcessFinder pipeline: %w", err)
	}
	tracerEventsCh := tracerEvents.Subscribe()
	pipeline.Start(ctx)
	return tracerEventsCh, nil
}

// connects the survey sub-pipeline to the pipe of kube enriched events, and forwards
// survey_info metrics from there
func (pf *ProcessFinder) connectSurveySubPipeline(swi *swarm.Instancer, kubeEnrichedEvents *msg.Queue[[]Event[processAttrs]]) {
	if !pf.cfg.Discovery.SurveyEnabled() {
		return
	}
	surveyFilteredEvents := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(SurveyCriteriaMatcherProvider(pf.cfg, kubeEnrichedEvents, surveyFilteredEvents))

	surveyExecutables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(ExecTyperProvider(pf.cfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer, surveyFilteredEvents, surveyExecutables))

	surveyExecutableTypes := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(ContainerDBUpdaterProvider(pf.ctxInfo.K8sInformer, surveyExecutables, surveyExecutableTypes))

	surveyEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	obiCfg := pf.cfg.AsOBI()
	swi.Add(SurveyEventGenerator(&obiCfg.Attributes.Kubernetes, pf.ctxInfo.K8sInformer, surveyExecutableTypes, surveyEvents))
	swi.Add(otel.SurveyInfoMetrics(pf.ctxInfo, &pf.cfg.Metrics, surveyEvents))
	swi.Add(prom.SurveyPrometheusEndpoint(pf.ctxInfo, &pf.cfg.Prometheus, surveyEvents))
}

// auxiliary functions to instantiate the go and non-go tracers on diverse steps of the
// discovery pipeline

// the common tracer group should get loaded for any tracer group, only once
func newCommonTracersGroup(cfg *beyla.Config) []ebpf.Tracer {
	obiCfg := cfg.AsOBI()
	switch cfg.EBPF.ContextPropagation {
	case config.ContextPropagationAll:
		return []ebpf.Tracer{tctracer.New(obiCfg), tpinjector.New(obiCfg)}
	case config.ContextPropagationHeadersOnly:
		return []ebpf.Tracer{tpinjector.New(obiCfg)}
	case config.ContextPropagationIPOptionsOnly:
		return []ebpf.Tracer{tctracer.New(obiCfg)}
	}

	return []ebpf.Tracer{}
}

func newGoTracersGroup(pidFilter ebpfcommon.ServiceFilter, cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{gotracer.New(pidFilter, cfg.AsOBI(), metrics)}
}

func newGenericTracersGroup(pidFilter ebpfcommon.ServiceFilter, cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	obiCfg := cfg.AsOBI()
	if cfg.EBPF.InstrumentGPU {
		return []ebpf.Tracer{generictracer.New(pidFilter, obiCfg, metrics), gpuevent.New(pidFilter, obiCfg, metrics)}
	}
	return []ebpf.Tracer{generictracer.New(pidFilter, obiCfg, metrics)}
}
