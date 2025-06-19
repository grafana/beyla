package discover

import (
	"context"
	"fmt"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/discover"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf"
	ebpfcommon "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/common"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/beyla"
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
func (pf *ProcessFinder) Start(ctx context.Context) (<-chan discover.Event[*ebpf.Instrumentable], error) {

	tracerEvents := msg.NewQueue[discover.Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	obiCfg := pf.cfg.AsOBI()

	swi := swarm.Instancer{}
	processEvents := msg.NewQueue[[]discover.Event[discover.ProcessAttrs]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(swarm.DirectInstance(discover.ProcessWatcherFunc(obiCfg, pf.ebpfEventContext, processEvents)))

	kubeEnrichedEvents := msg.NewQueue[[]discover.Event[discover.ProcessAttrs]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(discover.WatcherKubeEnricherProvider(pf.ctxInfo.K8sInformer, processEvents, kubeEnrichedEvents))
	pf.connectSurveySubPipeline(&swi, kubeEnrichedEvents)

	criteriaFilteredEvents := msg.NewQueue[[]discover.Event[discover.ProcessMatch]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(discover.CriteriaMatcherProvider(obiCfg, kubeEnrichedEvents, criteriaFilteredEvents))

	executableTypes := msg.NewQueue[[]discover.Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(discover.ExecTyperProvider(obiCfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer, criteriaFilteredEvents, executableTypes))

	// we could subscribe ContainerDBUpdater directly to the executableTypes queue and not providing any output channel
	// but forcing the output by the executableTypesReplica channel only after the Container DB has been updated
	// prevents race conditions in later stages of the pipeline
	storedExecutableTypes := msg.NewQueue[[]discover.Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(discover.ContainerDBUpdaterProvider(pf.ctxInfo.K8sInformer, executableTypes, storedExecutableTypes))

	swi.Add(discover.TraceAttacherProvider(&discover.TraceAttacher{
		Cfg:                  obiCfg,
		OutputTracerEvents:   tracerEvents,
		Metrics:              pf.ctxInfo.Metrics,
		SpanSignalsShortcut:  pf.tracesInput,
		InputInstrumentables: storedExecutableTypes,
		EbpfEventContext:     pf.ebpfEventContext,
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
func (pf *ProcessFinder) connectSurveySubPipeline(swi *swarm.Instancer, kubeEnrichedEvents *msg.Queue[[]discover.Event[discover.ProcessAttrs]]) {
	if !pf.cfg.Discovery.SurveyEnabled() {
		return
	}
	obiCfg := pf.cfg.AsOBI()

	surveyFilteredEvents := msg.NewQueue[[]discover.Event[discover.ProcessMatch]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(SurveyCriteriaMatcherProvider(pf.cfg, kubeEnrichedEvents, surveyFilteredEvents))

	surveyExecutables := msg.NewQueue[[]discover.Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(discover.ExecTyperProvider(obiCfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer, surveyFilteredEvents, surveyExecutables))

	surveyExecutableTypes := msg.NewQueue[[]discover.Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(discover.ContainerDBUpdaterProvider(pf.ctxInfo.K8sInformer, surveyExecutables, surveyExecutableTypes))

	surveyEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	obiCfg := pf.cfg.AsOBI()
	swi.Add(SurveyEventGenerator(&obiCfg.Attributes.Kubernetes, pf.ctxInfo.K8sInformer, surveyExecutableTypes, surveyEvents))
	swi.Add(otel.SurveyInfoMetrics(pf.ctxInfo, &pf.cfg.Metrics, surveyEvents))
	swi.Add(prom.SurveyPrometheusEndpoint(pf.ctxInfo, &pf.cfg.Prometheus, surveyEvents))
}
