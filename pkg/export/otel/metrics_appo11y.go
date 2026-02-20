package otel

import (
	"context"
	"debug/pe"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	"go.opentelemetry.io/otel/trace"
)

func mlog() *slog.Logger {
	return slog.With("component", "otel.AppO11yHostInfoMetricsReporter")
}

const (
	TracesHostInfo = "traces_host_info"
)

// GrafanaHostIDKey is the same attribute Key as HostIDKey, but used for
// traces_target_info
const GrafanaHostIDKey = attribute.Key("grafana.host.id")

// MetricsReporter implements the graph node that receives request.Span
// instances and forwards them as OTEL metrics.
type MetricsReporter struct {
	ctx              context.Context
	cfg              *otelcfg.MetricsConfig
	jointMetricsCfg  *perapp.MetricsConfig
	hostID           string
	attributes       *attributes.AttrSelector
	exporter         sdkmetric.Exporter
	hostInfo         *Expirer[*request.Span, instrument.Int64Gauge, int64]
	targetInfo       instrument.Int64UpDownCounter
	tracesTargetInfo instrument.Int64UpDownCounter
	pidTracker       otel.PidServiceTracker
	is               instrumentations.InstrumentationSelection
	attrGetters      attributes.NamedGetters[*request.Span, attribute.KeyValue]
	spanExtraAttrs   []attr.Name

	input         <-chan []request.Span
	processEvents <-chan exec.ProcessEvent

	log *slog.Logger
}

func ReportAppO11yHostMetrics(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	jointMetricsCfg *perapp.MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	unresolved request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !(cfg.EndpointEnabled() && jointMetricsCfg.Features.AppHost()) {
			return swarm.EmptyRunFunc()
		}
		otelcfg.SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		mr, err := newMetricsReporter(
			ctx,
			ctxInfo,
			cfg,
			jointMetricsCfg,
			selectorCfg,
			unresolved,
			input,
			processEventCh,
		)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL metrics reporter: %w", err)
		}

		return mr.reportMetrics, nil
	}
}

func newMetricsReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	jointMetricsCfg *perapp.MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	unresolved request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) (*MetricsReporter, error) {
	log := mlog()

	attribProvider, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, selectorCfg)
	if err != nil {
		return nil, fmt.Errorf("attributes select: %w", err)
	}

	is := instrumentations.NewInstrumentationSelection(cfg.Instrumentations)

	mr := MetricsReporter{
		ctx:             ctx,
		cfg:             cfg,
		jointMetricsCfg: jointMetricsCfg,
		is:              is,
		attributes:      attribProvider,
		hostID:          ctxInfo.HostID,
		input:           input.Subscribe(msg.SubscriberName("otelMetrics.InputSpans")),
		processEvents:   processEventCh.Subscribe(msg.SubscriberName("otelMetrics.ProcessEvents")),
		log:             mlog(),
		attrGetters:     request.SpanOTELGetters(unresolved),
	}

	mr.spanExtraAttrs = []attr.Name{}
	for _, label := range cfg.ExtraSpanResourceLabels {
		mr.spanExtraAttrs = append(mr.spanExtraAttrs, attr.Name(label))
	}

	// Instantiate the OTLP HTTP or GRPC metrics exporter
	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		return nil, err
	}
	mr.exporter = exporter

	mr.pidTracker = otel.NewPidServiceTracker()

	systemMetrics := mr.newMetricsInstance(nil)
	systemMeter := systemMetrics.provider.Meter(ReporterName)

	if err := mr.setupHostInfoMeter(systemMeter); err != nil {
		return nil, fmt.Errorf("setting up host metrics: %w", err)
	}

	return &mr, nil
}

func (mr *MetricsReporter) setupHostInfoMeter(meter instrument.Meter) error {
	tracesHostInfo, err := meter.Int64Gauge(TracesHostInfo)
	if err != nil {
		return fmt.Errorf("creating span metric traces host info: %w", err)
	}
	attr := attributes.Field[*request.Span, attribute.KeyValue]{
		ExposedName: string(GrafanaHostIDKey),
		Get: func(_ *request.Span) attribute.KeyValue {
			return semconv.HostID(mr.hostID)
		},
	}

	mr.hostInfo = NewExpirer[*request.Span, instrument.Int64Gauge, int64](
		mr.ctx, tracesHostInfo, []attributes.Field[*request.Span, attribute.KeyValue]{attr}, timeNow, mr.cfg.TTL)

	return nil
}

func (mr *MetricsReporter) close() {
	if err := mr.exporter.Shutdown(mr.ctx); err != nil {
		slog.With("component", "MetricsReporter").Error("closing metrics provider", "error", err)
	}
}

func (mr *MetricsReporter) setupPIDToServiceRelationship(pid app.PID, uid svc.UID) {
	mr.pidTracker.AddPID(pid, uid)
}

func (mr *MetricsReporter) disassociatePIDFromService(pid app.PID) (bool, svc.UID) {
	return mr.pidTracker.RemovePID(pid)
}

func (mr *MetricsReporter) reportMetrics(ctx context.Context) {
	defer mr.close()
	for {
		select {
		case <-ctx.Done():
			mr.log.Debug("context done, stopping metrics reporting")
			return
		case pe, ok := <-mr.processEvents:
			if !ok {
				mr.log.Debug("process events channel closed, stopping metrics reporting")
				return
			}
			mr.onProcessEvent(&pe)
		case spans, ok := <-mr.input:
			if !ok {
				mr.log.Debug("input channel closed, stopping metrics reporting")
				return
			}
			mr.onSpan(spans)
		}
	}
}

func (mr *MetricsReporter) onProcessEvent(pe *exec.ProcessEvent) {
	mr.log.Debug("Received new process event", "event type", pe.Type, "pid", pe.File.Pid, "attrs", pe.File.Service.UID)

	if pe.Type == exec.ProcessEventCreated {
		uid := pe.File.Service.UID

		// Handle the case when the PID changed its feathers, e.g. got new metadata impacting the service name.
		// There's no new PID, just an update to the metadata.
		if staleUID, exists := mr.pidTracker.TracksPID(pe.File.Pid); exists && !staleUID.Equals(&uid) {
			mr.log.Debug("updating older service definition", "from", staleUID, "new", uid)
			mr.pidTracker.ReplaceUID(staleUID, uid)
			// we don't setup the pid again, we just replaced the metrics it's associated with
			return
		}
		mr.setupPIDToServiceRelationship(pe.File.Pid, pe.File.Service.UID)
	} else {
		if deleted, origUID := mr.disassociatePIDFromService(pe.File.Pid); deleted {
			// We only need the UID to look up in the pool, no need to cache
			// the whole of the attrs in the pidTracker
			mr.log.Debug("deleting infos for", "pid", pe.File.Pid, "attrs", origUID)
			if mr.hostInfo != nil && mr.pidTracker.Count() == 0 {
				mlog().Debug("No more PIDs tracked, expiring host info metric")
				mr.hostInfo.RemoveAllMetrics(mr.ctx)
			}
		}
	}
}

func (mr *MetricsReporter) onSpan(spans []request.Span) {
	for i := range spans {
		s := &spans[i]
		if s.InternalSignal() {
			continue
		}
		if !s.Service.ExportModes.CanExportMetrics() {
			continue
		}
		hostInfo, attrs := mr.hostInfo.ForRecord(s)
		hostInfo.Record(mr.ctx, 1, instrument.WithAttributeSet(attrs))
	}
}

func (mr *MetricsReporter) newMeterProvider(service *svc.Attrs) *metric.MeterProvider {
	mlog := mlog()
	var resourceAttributes []attribute.KeyValue
	if service != nil {
		mlog = mlog.With("service", service)
		resourceAttributes = append(otelcfg.GetAppResourceAttrs(mr.hostID, service), otelcfg.ResourceAttrsFromEnv(service)...)
	}
	mlog.Debug("creating new Metrics reporter")
	resources := resource.NewWithAttributes(semconv.SchemaURL, resourceAttributes...)

	opts := []metric.Option{
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(mr.cfg.Interval))),
	}

	return Metrics{
		ctx:     mr.ctx,
		service: service,
		provider: metric.NewMeterProvider(
			opts...,
		),
	}
}
