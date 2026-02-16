package prom

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// using labels and names that are equivalent names to the OTEL attributes
// but following the different naming conventions
const (
	TracesHostInfo   = "traces_host_info"
	grafanaHostIDKey = "grafana_host_id"
)

var (
	hostInfoLabelNames = []string{grafanaHostIDKey}
)

func ahilog() *slog.Logger {
	return slog.With("component", "prom.AppO11yHostInfoMetricsReporter")
}

type appO11yHostInfoReporter struct {
	log                     *slog.Logger
	cfg                     *prom.PrometheusConfig
	extraMetadataLabels     []attr.Name
	extraSpanMetadataLabels []attr.Name

	input         <-chan []request.Span
	processEvents <-chan exec.ProcessEvent

	// trace span metrics
	tracesHostInfo *Expirer[prometheus.Gauge]

	promConnect *connector.PrometheusManager

	clock   *expire.CachedClock
	ctxInfo *global.ContextInfo

	is instrumentations.InstrumentationSelection

	kubeEnabled   bool
	dockerEnabled bool
	hostID        string

	pidsTracker otel.PidServiceTracker
}

func AppO11yHostInfoMetricsReporter(
	ctxInfo *global.ContextInfo,
	cfg *prom.PrometheusConfig,
	jointMetricsConfig *perapp.MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	unresolved request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.EndpointEnabled() || !jointMetricsConfig.Features.AppHost() {
			return swarm.EmptyRunFunc()
		}
		reporter, err := newReporter(ctx, ctxInfo, cfg, jointMetricsConfig, selectorCfg, unresolved, input, processEventCh)
		if err != nil {
			return nil, fmt.Errorf("instantiating Prometheus endpoint: %w", err)
		}
		if cfg.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

//nolint:cyclop
func newReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *prom.PrometheusConfig,
	jointMetricsConfig *perapp.MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	unresolved request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) (*appO11yHostInfoReporter, error) {
	groups := ctxInfo.MetricAttributeGroups
	groups.Add(attributes.GroupPrometheus)

	is := instrumentations.NewInstrumentationSelection(cfg.Instrumentations)

	kubeEnabled := ctxInfo.K8sInformer.IsKubeEnabled()
	dockerEnabled := ctxInfo.DockerMetadata.IsEnabled(ctx)

	clock := expire.NewCachedClock(timeNow)

	extraMetadataLabels := parseExtraMetadata(cfg.ExtraResourceLabels)
	extraSpanMetadataLabels := parseExtraMetadata(cfg.ExtraSpanResourceLabels)
	mr := &appO11yHostInfoReporter{
		log:                     ahilog(),
		input:                   input.Subscribe(msg.SubscriberName("prom.InputSpans")),
		processEvents:           processEventCh.Subscribe(msg.SubscriberName("prom.ProcessEvents")),
		pidsTracker:             otel.NewPidServiceTracker(),
		ctxInfo:                 ctxInfo,
		cfg:                     cfg,
		kubeEnabled:             kubeEnabled,
		dockerEnabled:           dockerEnabled,
		extraMetadataLabels:     extraMetadataLabels,
		extraSpanMetadataLabels: extraSpanMetadataLabels,
		hostID:                  ctxInfo.HostID,
		clock:                   clock,
		is:                      is,
		promConnect:             ctxInfo.Prometheus,
		tracesHostInfo: NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: TracesHostInfo,
			Help: "A metric with a constant '1' value labeled by the host id ",
		}, hostInfoLabelNames).MetricVec, clock.Time, cfg.TTL),
	}

	if mr.cfg.Registry != nil {
		mr.cfg.Registry.MustRegister(mr.tracesHostInfo)
	} else {
		mr.promConnect.Register(cfg.Port, cfg.Path, mr.tracesHostInfo)
	}

	return mr, nil
}

func optionalGaugeProvider(enable bool, provider func() *Expirer[prometheus.Gauge]) *Expirer[prometheus.Gauge] {
	if !enable {
		return nil
	}

	return provider()
}

func (r *appO11yHostInfoReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *appO11yHostInfoReporter) collectMetrics(ctx context.Context) {
	go r.watchForProcessEvents(ctx)
	swarms.ForEachInput(ctx, r.input, r.log.Debug, func(spans []request.Span) {
		// clock needs to be updated to let the expirer
		// remove the old metrics
		r.clock.Update()
		for i := range spans {
			r.observe(&spans[i])
		}
	})
}

func (r *appO11yHostInfoReporter) otelSpanFiltered(span *request.Span) bool {
	return span.InternalSignal() || request.IgnoreMetrics(span)
}

//nolint:cyclop
func (r *appO11yHostInfoReporter) observe(span *request.Span) {
	if r.otelSpanFiltered(span) {
		return
	}
	if !span.Service.ExportModes.CanExportMetrics() {
		return
	}
	if span.Service.Features.AppHost() {
		r.tracesHostInfo.WithLabelValues(r.hostID).Metric.Set(1.0)
	}
}

func (r *appO11yHostInfoReporter) watchForProcessEvents(ctx context.Context) {
	log := r.log.With("function", "watchForProcessEvents")
	swarms.ForEachInput(ctx, r.processEvents, log.Debug, func(pe exec.ProcessEvent) {
		r.handleProcessEvent(pe, log)
	})
}

func (r *appO11yHostInfoReporter) disassociatePIDFromService(pid app.PID) (bool, svc.UID) {
	return r.pidsTracker.RemovePID(pid)
}

func (r *appO11yHostInfoReporter) handleProcessEvent(pe exec.ProcessEvent, log *slog.Logger) {
	log.Debug("Received new process event", "event type", pe.Type, "pid", pe.File.Pid, "attrs", pe.File.Service.UID)
	uid := pe.File.Service.UID

	if pe.Type == exec.ProcessEventCreated {
		// Handle the case when the PID changed its feathers, e.g. got new metadata impacting the service name.
		// There's no new PID, just an update to the metadata.
		if staleUID, exists := r.pidsTracker.TracksPID(pe.File.Pid); exists && !staleUID.Equals(&uid) {
			log.Debug("updating older service definition", "from", staleUID, "new", uid)
			r.pidsTracker.ReplaceUID(staleUID, uid)
			return
		}
	} else {
		if deleted, _ := r.disassociatePIDFromService(pe.File.Pid); deleted {
			r.log.Debug("deleting infos for", "pid", pe.File.Pid, "attrs", pe.File.Service.UID)
			if r.pidsTracker.Count() == 0 {
				r.log.Debug("No more PIDs tracked, expiring host info metric")
				r.tracesHostInfo.entries.DeleteAll()
			}
		}
	}
}
