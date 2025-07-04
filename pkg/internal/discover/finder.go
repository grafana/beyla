package discover

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	obiDiscover "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/discover"
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
	obiProcessFinder *obiDiscover.ProcessFinder
}

func NewProcessFinder(
	cfg *beyla.Config,
	ctxInfo *global.ContextInfo,
	tracesInput *msg.Queue[[]request.Span],
	ebpfEventContext *ebpfcommon.EBPFEventContext) *ProcessFinder {
	return &ProcessFinder{
		cfg: cfg, ctxInfo: ctxInfo,
		obiProcessFinder: obiDiscover.NewProcessFinder(cfg.AsOBI(), ctxInfo, tracesInput, ebpfEventContext),
	}
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new obiDiscovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start(ctx context.Context) (<-chan obiDiscover.Event[*ebpf.Instrumentable], error) {

	enrichedProcessEvents := msg.NewQueue[[]obiDiscover.Event[obiDiscover.ProcessAttrs]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
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

// connects the survey sub-pipeline to the pipe of kube enriched events, and forwards
// survey_info metrics from there
func (pf *ProcessFinder) connectSurveySubPipeline(swi *swarm.Instancer, kubeEnrichedEvents *msg.Queue[[]obiDiscover.Event[obiDiscover.ProcessAttrs]]) {
	if !pf.cfg.Discovery.SurveyEnabled() {
		return
	}
	obiCfg := pf.cfg.AsOBI()

	surveyFilteredEvents := msg.NewQueue[[]obiDiscover.Event[obiDiscover.ProcessMatch]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(SurveyCriteriaMatcherProvider(pf.cfg, kubeEnrichedEvents, surveyFilteredEvents),
		swarm.WithID("SurveyCriteriaMatcherProvider"))

	surveyExecutables := msg.NewQueue[[]obiDiscover.Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(obiDiscover.ExecTyperProvider(obiCfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer, surveyFilteredEvents, surveyExecutables),
		swarm.WithID("SurveyExecTyperProvider"))

	surveyExecutableTypes := msg.NewQueue[[]obiDiscover.Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(obiDiscover.ContainerDBUpdaterProvider(pf.ctxInfo.K8sInformer, surveyExecutables, surveyExecutableTypes),
		swarm.WithID("SurveyContainerDBUpdaterProvider"))

	surveyEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(SurveyEventGenerator(&pf.cfg.Attributes.Kubernetes, pf.ctxInfo.K8sInformer, surveyExecutableTypes, surveyEvents),
		swarm.WithID("SurveyEventGenerator"))
	swi.Add(otel.SurveyInfoMetrics(pf.ctxInfo, &pf.cfg.Metrics, surveyEvents),
		swarm.WithID("SurveyInfoMetrics"))
	swi.Add(prom.SurveyPrometheusEndpoint(pf.ctxInfo, &pf.cfg.Prometheus, surveyEvents),
		swarm.WithID("SurveyPrometheusEndpoint"))
}
