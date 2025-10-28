// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func sglog() *slog.Logger {
	return slog.With("component", "otel.SvcGraphMetricsReporter")
}

const (
	ServiceGraphClient = "traces_service_graph_request_client"
	ServiceGraphServer = "traces_service_graph_request_server"
	ServiceGraphFailed = "traces_service_graph_request_failed_total"
	ServiceGraphTotal  = "traces_service_graph_request_total"
)

// MetricsReporter implements the graph node that receives request.Span
// instances and forwards them as OTEL metrics.
type SvcGraphMetricsReporter struct {
	ctx              context.Context
	cfg              *otelcfg.MetricsConfig
	hostID           string
	exporter         sdkmetric.Exporter
	reporters        otelcfg.ReporterPool[*svc.Attrs, *SvcGraphMetrics]
	pidTracker       PidServiceTracker
	is               instrumentations.InstrumentationSelection
	metricAttributes []attributes.Field[*request.Span, attribute.KeyValue]

	input         <-chan []request.Span
	processEvents <-chan exec.ProcessEvent

	log *slog.Logger
}

// SvcGraphMetrics is a set of metrics associated to a given OTEL MeterProvider.
// There is a Metrics instance for each service/process instrumented by OBI.
type SvcGraphMetrics struct {
	ctx                      context.Context
	service                  *svc.Attrs
	provider                 *metric.MeterProvider
	resourceAttributes       []attribute.KeyValue
	tracesResourceAttributes attribute.Set

	serviceGraphClient *Expirer[*request.Span, instrument.Float64Histogram, float64]
	serviceGraphServer *Expirer[*request.Span, instrument.Float64Histogram, float64]
	serviceGraphFailed *Expirer[*request.Span, instrument.Int64Counter, int64]
	serviceGraphTotal  *Expirer[*request.Span, instrument.Int64Counter, int64]
}

func ReportSvcGraphMetrics(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	unresolved request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
	processEvents *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.EndpointEnabled() || !cfg.ServiceGraphMetricsEnabled() {
			return swarm.EmptyRunFunc()
		}
		otelcfg.SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		mr, err := newSvcGraphMetricsReporter(
			ctx,
			ctxInfo,
			cfg,
			unresolved,
			input,
			processEvents,
		)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL metrics reporter: %w", err)
		}

		return mr.reportMetrics, nil
	}
}

func newSvcGraphMetricsReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	unresolved request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) (*SvcGraphMetricsReporter, error) {
	log := sglog()

	is := instrumentations.NewInstrumentationSelection(cfg.Instrumentations)

	mr := SvcGraphMetricsReporter{
		ctx:              ctx,
		cfg:              cfg,
		is:               is,
		hostID:           ctxInfo.HostID,
		input:            input.Subscribe(msg.SubscriberName("otel.SvcGraphMetricsReporter.input")),
		processEvents:    processEventCh.Subscribe(msg.SubscriberName("otel.SvcGraphMetricsReporter.processEvents")),
		metricAttributes: serviceGraphGetters(unresolved),
		log:              log,
	}

	mr.reporters = otelcfg.NewReporterPool[*svc.Attrs, *SvcGraphMetrics](cfg.ReportersCacheLen, cfg.TTL, timeNow,
		func(id svc.UID, v *SvcGraphMetrics) {
			llog := log.With("service", id)
			llog.Debug("evicting metrics reporter from cache")
			v.cleanupAllMetricsInstances()

			go func() {
				if err := v.provider.ForceFlush(ctx); err != nil {
					llog.Warn("error flushing evicted metrics provider", "error", err)
				}
			}()
		}, mr.newMetricSet)

	// Instantiate the OTLP HTTP or GRPC metrics exporter
	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		return nil, err
	}
	mr.exporter = instrumentMetricsExporter(ctxInfo.Metrics, exporter)

	mr.pidTracker = NewPidServiceTracker()

	return &mr, nil
}

func (mr *SvcGraphMetricsReporter) graphMetricOptions(log *slog.Logger) []metric.Option {
	useExponentialHistograms := isExponentialAggregation(mr.cfg, log)

	return []metric.Option{
		metric.WithView(otelHistogramConfig(ServiceGraphClient, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		metric.WithView(otelHistogramConfig(ServiceGraphServer, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
	}
}

func (mr *SvcGraphMetricsReporter) setupGraphMeters(m *SvcGraphMetrics, meter instrument.Meter) error {
	var err error

	serviceGraphClient, err := meter.Float64Histogram(ServiceGraphClient, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating service graph client histogram: %w", err)
	}
	m.serviceGraphClient = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
		m.ctx, serviceGraphClient, mr.metricAttributes, timeNow, mr.cfg.TTL)

	serviceGraphServer, err := meter.Float64Histogram(ServiceGraphServer, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating service graph server histogram: %w", err)
	}
	m.serviceGraphServer = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
		m.ctx, serviceGraphServer, mr.metricAttributes, timeNow, mr.cfg.TTL)

	serviceGraphFailed, err := meter.Int64Counter(ServiceGraphFailed)
	if err != nil {
		return fmt.Errorf("creating service graph failed total: %w", err)
	}
	m.serviceGraphFailed = NewExpirer[*request.Span, instrument.Int64Counter, int64](
		m.ctx, serviceGraphFailed, mr.metricAttributes, timeNow, mr.cfg.TTL)

	serviceGraphTotal, err := meter.Int64Counter(ServiceGraphTotal)
	if err != nil {
		return fmt.Errorf("creating service graph total: %w", err)
	}
	m.serviceGraphTotal = NewExpirer[*request.Span, instrument.Int64Counter, int64](
		m.ctx, serviceGraphTotal, mr.metricAttributes, timeNow, mr.cfg.TTL)

	return nil
}

func (mr *SvcGraphMetricsReporter) newSvcGraphMetricsInstance(service *svc.Attrs) *SvcGraphMetrics {
	log := mr.log
	var resourceAttributes []attribute.KeyValue
	if service != nil {
		log = log.With("service", service)
		resourceAttributes = append(otelcfg.GetAppResourceAttrs(mr.hostID, service), otelcfg.ResourceAttrsFromEnv(service)...)
	}
	log.Debug("creating new Metrics reporter")
	resources := resource.NewWithAttributes(semconv.SchemaURL, resourceAttributes...)

	opts := []metric.Option{
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(mr.cfg.Interval))),
	}

	opts = append(opts, mr.graphMetricOptions(log)...)

	return &SvcGraphMetrics{
		ctx:                      mr.ctx,
		service:                  service,
		resourceAttributes:       resourceAttributes,
		tracesResourceAttributes: mr.tracesResourceAttributes(service),
		provider: metric.NewMeterProvider(
			opts...,
		),
	}
}

func (mr *SvcGraphMetricsReporter) newMetricSet(service *svc.Attrs) (*SvcGraphMetrics, error) {
	m := mr.newSvcGraphMetricsInstance(service)

	mr.log.Debug("creating new metric set", "service", service)

	meter := m.provider.Meter(reporterName)

	if err := mr.setupGraphMeters(m, meter); err != nil {
		return nil, err
	}

	return m, nil
}

func (mr *SvcGraphMetricsReporter) close() {
	if err := mr.exporter.Shutdown(mr.ctx); err != nil {
		mr.log.Error("closing metrics provider", "error", err)
	}
}

func (mr *SvcGraphMetricsReporter) tracesResourceAttributes(service *svc.Attrs) attribute.Set {
	if service == nil {
		return *attribute.EmptySet()
	}
	baseAttrs := []attribute.KeyValue{
		semconv.ServiceName(service.UID.Name),
		semconv.ServiceInstanceID(service.UID.Instance),
		semconv.ServiceNamespace(service.UID.Namespace),
		semconv.TelemetrySDKLanguageKey.String(service.SDKLanguage.String()),
		semconv.TelemetrySDKNameKey.String("opentelemetry-ebpf-instrumentation"),
		request.SourceMetric(attr.VendorPrefix),
		semconv.OSTypeKey.String("linux"),
	}

	extraAttrs := []attribute.KeyValue{
		semconv.HostID(mr.hostID),
	}

	for k, v := range service.Metadata {
		extraAttrs = append(extraAttrs, k.OTEL().String(v))
	}

	filteredAttrs := otelcfg.GetFilteredAttributesByPrefix(baseAttrs, nil, extraAttrs, MetricTypes)
	return attribute.NewSet(filteredAttrs...)
}

func serviceGraphGetters(unresolved request.UnresolvedNames) []attributes.Field[*request.Span, attribute.KeyValue] {
	return attributes.OpenTelemetryGetters(
		request.SpanOTELGetters(unresolved), []attr.Name{
			attr.Client,
			attr.ClientNamespace,
			attr.Server,
			attr.ServerNamespace,
			attr.Source,
		})
}

func (r *SvcGraphMetrics) record(span *request.Span, mr *SvcGraphMetricsReporter) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()

	ctx := trace.ContextWithSpanContext(r.ctx, trace.SpanContext{}.WithTraceID(span.TraceID).WithSpanID(span.SpanID).WithTraceFlags(trace.TraceFlags(span.TraceFlags)))

	if !span.IsSelfReferenceSpan() || mr.cfg.AllowServiceGraphSelfReferences {
		if span.IsClientSpan() {
			sgc, attrs := r.serviceGraphClient.ForRecord(span)
			sgc.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			// If we managed to resolve the remote name only, we check to see
			// we are not instrumenting the server service, then and only then,
			// we generate client span count for service graph total
			if ClientSpanToUninstrumentedService(&mr.pidTracker, span) {
				sgt, attrs := r.serviceGraphTotal.ForRecord(span)
				sgt.Add(ctx, 1, instrument.WithAttributeSet(attrs))
			}
		} else {
			sgs, attrs := r.serviceGraphServer.ForRecord(span)
			sgs.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			sgt, attrs := r.serviceGraphTotal.ForRecord(span)
			sgt.Add(ctx, 1, instrument.WithAttributeSet(attrs))
		}
		if request.SpanStatusCode(span) == request.StatusCodeError {
			sgf, attrs := r.serviceGraphFailed.ForRecord(span)
			sgf.Add(ctx, 1, instrument.WithAttributeSet(attrs))
		}
	}
}

func ClientSpanToUninstrumentedService(tracker *PidServiceTracker, span *request.Span) bool {
	if span.HostName != "" {
		n := svc.ServiceNameNamespace{Name: span.HostName, Namespace: span.OtherNamespace}
		return !tracker.IsTrackingServerService(n)
	}
	// If we haven't resolved a hostname, don't add this node to the service graph
	// it will appear only in client requests. Essentially, in this case we have no
	// idea if the service is instrumented or not, therefore we take the conservative
	// approach to avoid double counting.
	return false
}

func (mr *SvcGraphMetricsReporter) setupPIDToServiceRelationship(pid int32, uid svc.UID) {
	mr.pidTracker.AddPID(pid, uid)
}

func (mr *SvcGraphMetricsReporter) disassociatePIDFromService(pid int32) (bool, svc.UID) {
	return mr.pidTracker.RemovePID(pid)
}

func (mr *SvcGraphMetricsReporter) reportMetrics(ctx context.Context) {
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

func (mr *SvcGraphMetricsReporter) onProcessEvent(pe *exec.ProcessEvent) {
	mr.log.Debug("Received new process event", "event type", pe.Type, "pid", pe.File.Pid, "attrs", pe.File.Service.UID)

	if pe.Type == exec.ProcessEventCreated {
		mr.setupPIDToServiceRelationship(pe.File.Pid, pe.File.Service.UID)
	} else {
		if deleted, origUID := mr.disassociatePIDFromService(pe.File.Pid); deleted {
			mr.log.Debug("deleting infos for",
				"pid", pe.File.Pid,
				"uid", origUID,
				"attrs", pe.File.Service)
		}
	}
}

func (mr *SvcGraphMetricsReporter) onSpan(spans []request.Span) {
	for i := range spans {
		s := &spans[i]
		if s.InternalSignal() {
			continue
		}
		if !s.Service.ExportModes.CanExportMetrics() {
			continue
		}
		// If we are ignoring this span because of route patterns, don't do anything
		if request.IgnoreMetrics(s) {
			continue
		}
		reporter, err := mr.reporters.For(&s.Service)
		if err != nil {
			mr.log.Error("unexpected error creating OTEL resource. Ignoring metric",
				"error", err, "service", s.Service)
			continue
		}
		reporter.record(s, mr)
	}
}

func (r *SvcGraphMetrics) cleanupAllMetricsInstances() {
	cleanupMetrics(r.ctx, r.serviceGraphClient)
	cleanupMetrics(r.ctx, r.serviceGraphServer)
	cleanupCounterMetrics(r.ctx, r.serviceGraphFailed)
	cleanupCounterMetrics(r.ctx, r.serviceGraphTotal)
}
