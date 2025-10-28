package discover

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/export/prom"
)

type ProcessFinder struct {
	cfg              *beyla.Config
	ctxInfo          *global.ContextInfo
	ebpfEventContext *ebpfcommon.EBPFEventContext
	obiProcessFinder *obiDiscover.ProcessFinder
}

func NewProcessFinder(
	cfg *beyla.Config,
	ctxInfo *global.ContextInfo,
	tracesInput *msg.Queue[[]request.Span],
	ebpfEventContext *ebpfcommon.EBPFEventContext) *ProcessFinder {
	return &ProcessFinder{
		cfg: cfg, ctxInfo: ctxInfo,
		ebpfEventContext: ebpfEventContext,
		obiProcessFinder: obiDiscover.NewProcessFinder(cfg.AsOBI(), ctxInfo, tracesInput, ebpfEventContext),
	}
}

func (pf *ProcessFinder) startSuveyPipeline(ctx context.Context) (<-chan obiDiscover.Event[*ebpf.Instrumentable], error) {
	swi := swarm.Instancer{}
	processEvents := msg.NewQueue[[]obiDiscover.Event[obiDiscover.ProcessAttrs]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("processEvents"))

	obiCfg := pf.cfg.AsOBI()

	swi.Add(swarm.DirectInstance(obiDiscover.ProcessWatcherFunc(obiCfg, pf.ebpfEventContext, processEvents)),
		swarm.WithID("ProcessWatcher"))

	enrichedProcessEvents := msg.NewQueue[[]obiDiscover.Event[obiDiscover.ProcessAttrs]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("enrichedProcessEvents"))

	swi.Add(obiDiscover.WatcherKubeEnricherProvider(pf.ctxInfo.K8sInformer, processEvents, enrichedProcessEvents),
		swarm.WithID("WatcherKubeEnricher"))

	pf.connectSurveySubPipeline(&swi, enrichedProcessEvents)

	pipeline, err := swi.Instance(ctx)

	if err != nil {
		return nil, fmt.Errorf("can't instantiate obiDiscovery.ProcessFinder pipeline: %w", err)
	}

	log := slog.With("component", "discovery.ProcessFinder")
	log.Debug("starting survey mode pipeline")

	pipeline.Start(ctx)

	return nil, nil
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new obiDiscovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) startMixedPipeline(ctx context.Context) (<-chan obiDiscover.Event[*ebpf.Instrumentable], error) {

	enrichedProcessEvents := msg.NewQueue[[]obiDiscover.Event[obiDiscover.ProcessAttrs]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("enrichedProcessEvents"))
	swi := swarm.Instancer{}
	obiPFStart := make(chan (<-chan obiDiscover.Event[*ebpf.Instrumentable]), 1)
	pf.connectSurveySubPipeline(&swi, enrichedProcessEvents)

	// runs the OBI's process finder pipeline in a subnode, and listens for the enriched process events
	// to connect there the Beyla survey pipeline
	swi.Add(func(ctx context.Context) (swarm.RunFunc, error) {
		instrumentableEvents, err := pf.obiProcessFinder.Start(ctx,
			obiDiscover.WithEnrichedProcessEvents(enrichedProcessEvents))
		if err != nil {
			return nil, err
		}
		obiPFStart <- instrumentableEvents
		return func(_ context.Context) {
			<-pf.obiProcessFinder.Done()
		}, err
	}, swarm.WithID("OBIProcessFinderSubPipeline"))

	pipeline, err := swi.Instance(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't instantiate obiDiscovery.ProcessFinder pipeline: %w", err)
	}
	log := slog.With("component", "discovery.ProcessFinder")
	log.Debug("waiting for OBI internal ProcessFinder instantiator to return the tracer's channel")
	tracerEventsCh := <-obiPFStart
	log.Debug("starting OBI internal ProcessFinder pipeline")
	pipeline.Start(ctx)
	return tracerEventsCh, nil
}

func (pf *ProcessFinder) Start(ctx context.Context) (<-chan obiDiscover.Event[*ebpf.Instrumentable], error) {
	if pf.IsInstrumentationEnabled() {
		return pf.startMixedPipeline(ctx)
	}

	return pf.startSuveyPipeline(ctx)
}

func (pf *ProcessFinder) IsInstrumentationEnabled() bool {
	c := pf.cfg

	return c.Port.Len() > 0 || c.AutoTargetExe.IsSet() || c.Exec.IsSet() ||
		c.Exec.IsSet() || c.Discovery.AppDiscoveryEnabled()
}

// connects the survey sub-pipeline to the pipe of kube enriched events, and forwards
// survey_info metrics from there
func (pf *ProcessFinder) connectSurveySubPipeline(swi *swarm.Instancer, kubeEnrichedEvents *msg.Queue[[]obiDiscover.Event[obiDiscover.ProcessAttrs]]) {
	if !pf.cfg.Discovery.SurveyEnabled() {
		return
	}
	obiCfg := pf.cfg.AsOBI()

	surveyFilteredEvents := msg.NewQueue[[]obiDiscover.Event[obiDiscover.ProcessMatch]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("surveyFilteredEvents"))
	swi.Add(SurveyCriteriaMatcherProvider(pf.cfg, kubeEnrichedEvents, surveyFilteredEvents),
		swarm.WithID("SurveyCriteriaMatcherProvider"))

	surveyExecutables := msg.NewQueue[[]obiDiscover.Event[ebpf.Instrumentable]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("surveyExecutables"))
	swi.Add(obiDiscover.ExecTyperProvider(obiCfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer, surveyFilteredEvents, surveyExecutables),
		swarm.WithID("SurveyExecTyperProvider"))

	surveyExecutableTypes := msg.NewQueue[[]obiDiscover.Event[ebpf.Instrumentable]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("surveyExecutableTypes"))
	swi.Add(obiDiscover.ContainerDBUpdaterProvider(pf.ctxInfo.K8sInformer, surveyExecutables, surveyExecutableTypes),
		swarm.WithID("SurveyContainerDBUpdaterProvider"))

	surveyEvents := msg.NewQueue[exec.ProcessEvent](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("surveyEvents"))
	swi.Add(SurveyEventGenerator(&pf.cfg.Attributes.Kubernetes, pf.ctxInfo.K8sInformer, surveyExecutableTypes, surveyEvents),
		swarm.WithID("SurveyEventGenerator"))
	swi.Add(otel.SurveyInfoMetrics(pf.ctxInfo, &pf.cfg.Metrics, surveyEvents),
		swarm.WithID("SurveyInfoMetrics"))
	swi.Add(prom.SurveyPrometheusEndpoint(pf.ctxInfo, &pf.cfg.Prometheus, surveyEvents),
		swarm.WithID("SurveyPrometheusEndpoint"))
}
