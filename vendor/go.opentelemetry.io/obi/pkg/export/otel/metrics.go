// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func mlog() *slog.Logger {
	return slog.With("component", "otel.MetricsReporter")
}

const (
	// SpanMetricsLatency and rest of metrics below haven't been yet moved to the
	// pkg/internal/export/metric package as we are disabling user-provided attribute
	// selection for them. They are very specific metrics with an opinionated format
	// for Span Metrics and Service Graph Metrics functionalities
	SpanMetricsLatency       = "traces_spanmetrics_latency"
	SpanMetricsLatencyOTel   = "traces_span_metrics_duration"
	SpanMetricsCalls         = "traces_spanmetrics_calls_total"
	SpanMetricsCallsOTel     = "traces_span_metrics_calls_total"
	SpanMetricsRequestSizes  = "traces_spanmetrics_size_total"
	SpanMetricsResponseSizes = "traces_spanmetrics_response_size_total"
	TracesTargetInfo         = "traces_target_info"
	TargetInfo               = "target_info"
	TracesHostInfo           = "traces_host_info"

	AggregationExplicit    = "explicit_bucket_histogram"
	AggregationExponential = "base2_exponential_bucket_histogram"
)

// GrafanaHostIDKey is the same attribute Key as HostIDKey, but used for
// traces_target_info
const GrafanaHostIDKey = attribute.Key("grafana.host.id")

// MetricTypes contains all the supported metric type prefixes used for filtering attributes
var MetricTypes = []string{
	"http.server", "http.client",
	"rpc.server", "rpc.client",
	"db.client",
	"messaging.",
}

// MetricsReporter implements the graph node that receives request.Span
// instances and forwards them as OTEL metrics.
type MetricsReporter struct {
	ctx              context.Context
	cfg              *otelcfg.MetricsConfig
	hostID           string
	attributes       *attributes.AttrSelector
	exporter         sdkmetric.Exporter
	reporters        otelcfg.ReporterPool[*svc.Attrs, *Metrics]
	hostInfo         *Expirer[*request.Span, instrument.Int64Gauge, int64]
	targetInfo       instrument.Int64UpDownCounter
	tracesTargetInfo instrument.Int64UpDownCounter
	pidTracker       PidServiceTracker
	is               instrumentations.InstrumentationSelection
	targetMetrics    map[svc.UID]*TargetMetrics
	attrGetters      attributes.NamedGetters[*request.Span, attribute.KeyValue]

	// user-selected fields for each of the reported metrics
	attrHTTPDuration           []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPClientDuration     []attributes.Field[*request.Span, attribute.KeyValue]
	attrGRPCServer             []attributes.Field[*request.Span, attribute.KeyValue]
	attrGRPCClient             []attributes.Field[*request.Span, attribute.KeyValue]
	attrDBClient               []attributes.Field[*request.Span, attribute.KeyValue]
	attrMessagingPublish       []attributes.Field[*request.Span, attribute.KeyValue]
	attrMessagingProcess       []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPRequestSize        []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPResponseSize       []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPClientRequestSize  []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPClientResponseSize []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUKernelCalls         []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUKernelGridSize      []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUKernelBlockSize     []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUMemoryAllocations   []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUMemoryCopies        []attributes.Field[*request.Span, attribute.KeyValue]
	userAttribSelection        attributes.Selection
	input                      <-chan []request.Span
	processEvents              <-chan exec.ProcessEvent

	log *slog.Logger

	// testing support
	createEventMetrics func(targetMetrics *TargetMetrics)
	deleteEventMetrics func(targetMetrics *TargetMetrics)
}

// Metrics is a set of metrics associated to a given OTEL MeterProvider.
// There is a Metrics instance for each service/process instrumented by OBI.
type Metrics struct {
	ctx      context.Context
	service  *svc.Attrs
	provider *metric.MeterProvider

	// IMPORTANT! Don't forget to clean each Expirer in cleanupAllMetricsInstances method
	httpDuration           *Expirer[*request.Span, instrument.Float64Histogram, float64]
	httpClientDuration     *Expirer[*request.Span, instrument.Float64Histogram, float64]
	grpcDuration           *Expirer[*request.Span, instrument.Float64Histogram, float64]
	grpcClientDuration     *Expirer[*request.Span, instrument.Float64Histogram, float64]
	dbClientDuration       *Expirer[*request.Span, instrument.Float64Histogram, float64]
	msgPublishDuration     *Expirer[*request.Span, instrument.Float64Histogram, float64]
	msgProcessDuration     *Expirer[*request.Span, instrument.Float64Histogram, float64]
	httpRequestSize        *Expirer[*request.Span, instrument.Float64Histogram, float64]
	httpResponseSize       *Expirer[*request.Span, instrument.Float64Histogram, float64]
	httpClientRequestSize  *Expirer[*request.Span, instrument.Float64Histogram, float64]
	httpClientResponseSize *Expirer[*request.Span, instrument.Float64Histogram, float64]
	// trace span metrics
	spanMetricsLatency           *Expirer[*request.Span, instrument.Float64Histogram, float64]
	spanMetricsCallsTotal        *Expirer[*request.Span, instrument.Int64Counter, int64]
	spanMetricsRequestSizeTotal  *Expirer[*request.Span, instrument.Float64Counter, float64]
	spanMetricsResponseSizeTotal *Expirer[*request.Span, instrument.Float64Counter, float64]
	gpuKernelCallsTotal          *Expirer[*request.Span, instrument.Int64Counter, int64]
	gpuMemoryAllocsTotal         *Expirer[*request.Span, instrument.Int64Counter, int64]
	gpuKernelGridSize            *Expirer[*request.Span, instrument.Float64Histogram, float64]
	gpuKernelBlockSize           *Expirer[*request.Span, instrument.Float64Histogram, float64]
	gpuMemoryCopySize            *Expirer[*request.Span, instrument.Float64Histogram, float64]
}

type TargetMetrics struct {
	resourceAttributes       attribute.Set
	tracesResourceAttributes attribute.Set
}

func ReportMetrics(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	unresolved request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		otelcfg.SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		mr, err := newMetricsReporter(
			ctx,
			ctxInfo,
			cfg,
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
		ctx:                 ctx,
		cfg:                 cfg,
		is:                  is,
		targetMetrics:       map[svc.UID]*TargetMetrics{},
		attributes:          attribProvider,
		hostID:              ctxInfo.HostID,
		input:               input.Subscribe(msg.SubscriberName("otelMetrics.InputSpans")),
		processEvents:       processEventCh.Subscribe(msg.SubscriberName("otelMetrics.ProcessEvents")),
		userAttribSelection: selectorCfg.SelectionCfg,
		log:                 mlog(),
		attrGetters:         request.SpanOTELGetters(unresolved),
	}

	mr.createEventMetrics = mr.createTargetMetricData
	mr.deleteEventMetrics = mr.deleteTargetMetricData

	// initialize attribute getters
	if is.HTTPEnabled() {
		mr.attrHTTPDuration = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.HTTPServerDuration))
		mr.attrHTTPClientDuration = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.HTTPClientDuration))
		mr.attrHTTPRequestSize = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.HTTPServerRequestSize))
		mr.attrHTTPResponseSize = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.HTTPServerResponseSize))
		mr.attrHTTPClientRequestSize = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.HTTPClientRequestSize))
		mr.attrHTTPClientResponseSize = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.HTTPClientResponseSize))
	}

	if is.GRPCEnabled() {
		mr.attrGRPCServer = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.RPCServerDuration))
		mr.attrGRPCClient = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.RPCClientDuration))
	}

	if is.DBEnabled() {
		mr.attrDBClient = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.DBClientDuration))
	}

	if is.MQEnabled() {
		mr.attrMessagingPublish = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.MessagingPublishDuration))
		mr.attrMessagingProcess = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.MessagingProcessDuration))
	}

	if is.GPUEnabled() {
		mr.attrGPUKernelCalls = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.GPUKernelLaunchCalls))
		mr.attrGPUMemoryAllocations = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.GPUMemoryAllocations))
		mr.attrGPUKernelGridSize = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.GPUKernelGridSize))
		mr.attrGPUKernelBlockSize = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.GPUKernelBlockSize))
		mr.attrGPUMemoryCopies = attributes.OpenTelemetryGetters(
			mr.attrGetters, mr.attributes.For(attributes.GPUMemoryCopies))
	}

	mr.reporters = otelcfg.NewReporterPool[*svc.Attrs, *Metrics](cfg.ReportersCacheLen, cfg.TTL, timeNow,
		func(id svc.UID, v *Metrics) {
			llog := log.With("service", id)
			llog.Debug("evicting metrics reporter from cache")
			v.cleanupAllMetricsInstances()

			if !mr.pidTracker.ServiceLive(id) {
				mr.deleteTargetMetrics(&id)
			}

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

	systemMetrics := mr.newMetricsInstance(nil)
	systemMeter := systemMetrics.provider.Meter(reporterName)

	if cfg.HostMetricsEnabled() {
		err := mr.setupHostInfoMeter(systemMeter)
		if err != nil {
			return nil, fmt.Errorf("setting up host metrics: %w", err)
		}
	}

	if err := mr.setupTargetInfo(systemMeter); err != nil {
		return nil, fmt.Errorf("setting up target info: %w", err)
	}

	if err := mr.setupTracesTargetInfo(systemMeter); err != nil {
		return nil, fmt.Errorf("setting up traces target info: %w", err)
	}

	return &mr, nil
}

func (mr *MetricsReporter) otelMetricOptions(mlog *slog.Logger) []metric.Option {
	var opts []metric.Option
	if !mr.cfg.OTelMetricsEnabled() {
		return opts
	}

	useExponentialHistograms := isExponentialAggregation(mr.cfg, mlog)

	if mr.is.HTTPEnabled() {
		opts = append(opts,
			metric.WithView(otelHistogramConfig(attributes.HTTPServerDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.HTTPClientDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.HTTPServerRequestSize.OTEL, mr.cfg.Buckets.RequestSizeHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.HTTPServerResponseSize.OTEL, mr.cfg.Buckets.ResponseSizeHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.HTTPClientRequestSize.OTEL, mr.cfg.Buckets.RequestSizeHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.HTTPClientResponseSize.OTEL, mr.cfg.Buckets.ResponseSizeHistogram, useExponentialHistograms)),
		)
	}

	if mr.is.GRPCEnabled() {
		opts = append(opts,
			metric.WithView(otelHistogramConfig(attributes.RPCServerDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.RPCClientDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		)
	}

	if mr.is.DBEnabled() {
		opts = append(opts,
			metric.WithView(otelHistogramConfig(attributes.DBClientDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		)
	}

	if mr.is.MQEnabled() {
		opts = append(opts,
			metric.WithView(otelHistogramConfig(attributes.MessagingPublishDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.MessagingProcessDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		)
	}

	return opts
}

func (mr *MetricsReporter) usesLegacySpanNames() bool {
	return slices.Contains(mr.cfg.Features, otelcfg.FeatureSpan)
}

func (mr *MetricsReporter) spanMetricsLatencyName() string {
	if mr.usesLegacySpanNames() {
		return SpanMetricsLatency
	}

	return SpanMetricsLatencyOTel
}

func (mr *MetricsReporter) spanMetricOptions(mlog *slog.Logger) []metric.Option {
	if !mr.cfg.SpanMetricsEnabled() {
		return []metric.Option{}
	}

	useExponentialHistograms := isExponentialAggregation(mr.cfg, mlog)

	return []metric.Option{
		metric.WithView(otelHistogramConfig(mr.spanMetricsLatencyName(), mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
	}
}

func (mr *MetricsReporter) setupTargetInfo(meter instrument.Meter) error {
	var err error
	mr.targetInfo, err = meter.Int64UpDownCounter(TargetInfo, instrument.WithDescription("Target metadata"))
	if err != nil {
		return fmt.Errorf("creating target info: %w", err)
	}

	return nil
}

// nolint: cyclop
func (mr *MetricsReporter) setupOtelMeters(m *Metrics, meter instrument.Meter) error {
	if !mr.cfg.OTelMetricsEnabled() {
		return nil
	}

	if mr.is.HTTPEnabled() {
		httpDuration, err := meter.Float64Histogram(attributes.HTTPServerDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating http duration histogram metric: %w", err)
		}
		m.httpDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpDuration, mr.attrHTTPDuration, timeNow, mr.cfg.TTL)

		httpClientDuration, err := meter.Float64Histogram(attributes.HTTPClientDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating http duration histogram metric: %w", err)
		}
		m.httpClientDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpClientDuration, mr.attrHTTPClientDuration, timeNow, mr.cfg.TTL)

		httpRequestSize, err := meter.Float64Histogram(attributes.HTTPServerRequestSize.OTEL, instrument.WithUnit("By"))
		if err != nil {
			return fmt.Errorf("creating http request size histogram metric: %w", err)
		}
		m.httpRequestSize = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpRequestSize, mr.attrHTTPRequestSize, timeNow, mr.cfg.TTL)

		httpResponseSize, err := meter.Float64Histogram(attributes.HTTPServerResponseSize.OTEL, instrument.WithUnit("By"))
		if err != nil {
			return fmt.Errorf("creating http response size histogram metric: %w", err)
		}
		m.httpResponseSize = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpResponseSize, mr.attrHTTPResponseSize, timeNow, mr.cfg.TTL)

		httpClientRequestSize, err := meter.Float64Histogram(attributes.HTTPClientRequestSize.OTEL, instrument.WithUnit("By"))
		if err != nil {
			return fmt.Errorf("creating http client request size histogram metric: %w", err)
		}
		m.httpClientRequestSize = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpClientRequestSize, mr.attrHTTPClientRequestSize, timeNow, mr.cfg.TTL)

		httpClientResponseSize, err := meter.Float64Histogram(attributes.HTTPClientResponseSize.OTEL, instrument.WithUnit("By"))
		if err != nil {
			return fmt.Errorf("creating http client response size histogram metric: %w", err)
		}
		m.httpClientResponseSize = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpClientResponseSize, mr.attrHTTPClientResponseSize, timeNow, mr.cfg.TTL)
	}

	if mr.is.GRPCEnabled() {
		grpcDuration, err := meter.Float64Histogram(attributes.RPCServerDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating grpc duration histogram metric: %w", err)
		}
		m.grpcDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, grpcDuration, mr.attrGRPCServer, timeNow, mr.cfg.TTL)

		grpcClientDuration, err := meter.Float64Histogram(attributes.RPCClientDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating grpc duration histogram metric: %w", err)
		}
		m.grpcClientDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, grpcClientDuration, mr.attrGRPCClient, timeNow, mr.cfg.TTL)
	}

	if mr.is.DBEnabled() {
		dbClientDuration, err := meter.Float64Histogram(attributes.DBClientDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating db client duration histogram metric: %w", err)
		}
		m.dbClientDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, dbClientDuration, mr.attrDBClient, timeNow, mr.cfg.TTL)
	}

	if mr.is.MQEnabled() {
		msgPublishDuration, err := meter.Float64Histogram(attributes.MessagingPublishDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating messaging client publish duration histogram metric: %w", err)
		}
		m.msgPublishDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, msgPublishDuration, mr.attrMessagingPublish, timeNow, mr.cfg.TTL)

		msgProcessDuration, err := meter.Float64Histogram(attributes.MessagingProcessDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating messaging client process duration histogram metric: %w", err)
		}
		m.msgProcessDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, msgProcessDuration, mr.attrMessagingProcess, timeNow, mr.cfg.TTL)
	}

	if mr.is.GPUEnabled() {
		gpuKernelCallsTotal, err := meter.Int64Counter(attributes.GPUKernelLaunchCalls.OTEL)
		if err != nil {
			return fmt.Errorf("creating gpu kernel calls total: %w", err)
		}
		m.gpuKernelCallsTotal = NewExpirer[*request.Span, instrument.Int64Counter, int64](
			m.ctx, gpuKernelCallsTotal, mr.attrGPUKernelCalls, timeNow, mr.cfg.TTL)

		gpuMemoryAllocationsTotal, err := meter.Int64Counter(attributes.GPUMemoryAllocations.OTEL, instrument.WithUnit("By"))
		if err != nil {
			return fmt.Errorf("creating gpu memory allocations total: %w", err)
		}
		m.gpuMemoryAllocsTotal = NewExpirer[*request.Span, instrument.Int64Counter, int64](
			m.ctx, gpuMemoryAllocationsTotal, mr.attrGPUMemoryAllocations, timeNow, mr.cfg.TTL)

		gpuKernelGridSize, err := meter.Float64Histogram(attributes.GPUKernelGridSize.OTEL, instrument.WithUnit("1"))
		if err != nil {
			return fmt.Errorf("creating gpu kernel grid size histogram: %w", err)
		}
		m.gpuKernelGridSize = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, gpuKernelGridSize, mr.attrGPUKernelGridSize, timeNow, mr.cfg.TTL)

		gpuKernelBlockSize, err := meter.Float64Histogram(attributes.GPUKernelBlockSize.OTEL, instrument.WithUnit("1"))
		if err != nil {
			return fmt.Errorf("creating gpu kernel block size histogram: %w", err)
		}
		m.gpuKernelBlockSize = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, gpuKernelBlockSize, mr.attrGPUKernelBlockSize, timeNow, mr.cfg.TTL)

		gpuMemoryCopySize, err := meter.Float64Histogram(attributes.GPUMemoryCopies.OTEL, instrument.WithUnit("1"))
		if err != nil {
			return fmt.Errorf("creating gpu memcpy size histogram: %w", err)
		}
		m.gpuMemoryCopySize = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, gpuMemoryCopySize, mr.attrGPUMemoryCopies, timeNow, mr.cfg.TTL)
	}

	return nil
}

func (mr *MetricsReporter) spanMetricsCallsName() string {
	if mr.usesLegacySpanNames() {
		return SpanMetricsCalls
	}

	return SpanMetricsCallsOTel
}

func (mr *MetricsReporter) setupSpanSizeMeters(m *Metrics, meter instrument.Meter) error {
	if !mr.cfg.SpanMetricsSizesEnabled() {
		return nil
	}

	var err error

	spanMetricAttrs := mr.spanMetricAttributes()

	spanMetricsRequestSizeTotal, err := meter.Float64Counter(SpanMetricsRequestSizes)
	if err != nil {
		return fmt.Errorf("creating span metric request size total: %w", err)
	}
	m.spanMetricsRequestSizeTotal = NewExpirer[*request.Span, instrument.Float64Counter, float64](
		m.ctx, spanMetricsRequestSizeTotal, spanMetricAttrs, timeNow, mr.cfg.TTL)

	spanMetricsResponseSizeTotal, err := meter.Float64Counter(SpanMetricsResponseSizes)
	if err != nil {
		return fmt.Errorf("creating span metric response size total: %w", err)
	}
	m.spanMetricsResponseSizeTotal = NewExpirer[*request.Span, instrument.Float64Counter, float64](
		m.ctx, spanMetricsResponseSizeTotal, spanMetricAttrs, timeNow, mr.cfg.TTL)

	return nil
}

func (mr *MetricsReporter) setupTracesTargetInfo(meter instrument.Meter) error {
	var err error

	mr.tracesTargetInfo, err = meter.Int64UpDownCounter(TracesTargetInfo)
	if err != nil {
		return fmt.Errorf("creating span metric traces target info: %w", err)
	}

	return nil
}

func (mr *MetricsReporter) setupSpanMeters(m *Metrics, meter instrument.Meter) error {
	if !mr.cfg.SpanMetricsEnabled() {
		return nil
	}

	var err error

	spanMetricAttrs := mr.spanMetricAttributes()

	instrumentOpts := []instrument.Float64HistogramOption{}

	if !mr.usesLegacySpanNames() {
		instrumentOpts = append(instrumentOpts, instrument.WithUnit("s"))
	}

	spanMetricsLatency, err := meter.Float64Histogram(mr.spanMetricsLatencyName(), instrumentOpts...)
	if err != nil {
		return fmt.Errorf("creating span metric histogram for latency: %w", err)
	}
	m.spanMetricsLatency = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
		m.ctx, spanMetricsLatency, spanMetricAttrs, timeNow, mr.cfg.TTL)

	spanMetricsCallsTotal, err := meter.Int64Counter(mr.spanMetricsCallsName())
	if err != nil {
		return fmt.Errorf("creating span metric calls total: %w", err)
	}
	m.spanMetricsCallsTotal = NewExpirer[*request.Span, instrument.Int64Counter, int64](
		m.ctx, spanMetricsCallsTotal, spanMetricAttrs, timeNow, mr.cfg.TTL)

	return nil
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

func (mr *MetricsReporter) newMetricsInstance(service *svc.Attrs) Metrics {
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

	opts = append(opts, mr.otelMetricOptions(mlog)...)
	opts = append(opts, mr.spanMetricOptions(mlog)...)

	return Metrics{
		ctx:     mr.ctx,
		service: service,
		provider: metric.NewMeterProvider(
			opts...,
		),
	}
}

func (mr *MetricsReporter) newMetricSet(service *svc.Attrs) (*Metrics, error) {
	m := mr.newMetricsInstance(service)

	mlog().Debug("creating new metric set", "service", service)
	// time units for HTTP and GRPC durations are in seconds, according to the OTEL specification:
	// https://github.com/open-telemetry/opentelemetry-specification/tree/main/specification/metrics/semantic_conventions
	// TODO: set ExplicitBucketBoundaries here and in prometheus from the previous specification
	meter := m.provider.Meter(reporterName)
	var err error

	if mr.cfg.OTelMetricsEnabled() {
		err = mr.setupOtelMeters(&m, meter)
		if err != nil {
			return nil, err
		}
	}

	if mr.cfg.SpanMetricsEnabled() {
		err = mr.setupSpanMeters(&m, meter)
		if err != nil {
			return nil, err
		}
	}

	if mr.cfg.SpanMetricsSizesEnabled() {
		err = mr.setupSpanSizeMeters(&m, meter)
		if err != nil {
			return nil, err
		}
	}

	return &m, nil
}

func isExponentialAggregation(mc *otelcfg.MetricsConfig, mlog *slog.Logger) bool {
	switch mc.HistogramAggregation {
	case AggregationExponential:
		return true
	case AggregationExplicit:
	// do nothing
	default:
		mlog.Warn("invalid value for histogram aggregation. Accepted values are: "+
			AggregationExponential+", "+AggregationExplicit+" (default). Using default",
			"value", mc.HistogramAggregation)
	}
	return false
}

func (mr *MetricsReporter) close() {
	if err := mr.exporter.Shutdown(mr.ctx); err != nil {
		slog.With("component", "MetricsReporter").Error("closing metrics provider", "error", err)
	}
}

// instrumentMetricsExporter checks whether the context is configured to report internal metrics and,
// in this case, wraps the passed metrics exporter inside an instrumented exporter
func instrumentMetricsExporter(internalMetrics imetrics.Reporter, in sdkmetric.Exporter) sdkmetric.Exporter {
	// avoid wrapping the instrumented exporter if we don't have
	// internal instrumentation (NoopReporter)
	if _, ok := internalMetrics.(imetrics.NoopReporter); ok || internalMetrics == nil {
		return in
	}
	return &instrumentedMetricsExporter{
		Exporter: in,
		internal: internalMetrics,
	}
}

func otelHistogramConfig(metricName string, buckets []float64, useExponentialHistogram bool) metric.View {
	if useExponentialHistogram {
		return metric.NewView(
			metric.Instrument{
				Name:  metricName,
				Scope: instrumentation.Scope{Name: reporterName},
			},
			metric.Stream{
				Name: metricName,
				Aggregation: sdkmetric.AggregationBase2ExponentialHistogram{
					MaxScale: 20,
					MaxSize:  160,
				},
			})
	}
	return metric.NewView(
		metric.Instrument{
			Name:  metricName,
			Scope: instrumentation.Scope{Name: reporterName},
		},
		metric.Stream{
			Name: metricName,
			Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: buckets,
			},
		})
}

func (mr *MetricsReporter) tracesResourceAttributes(service *svc.Attrs) attribute.Set {
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

	filteredAttrs := otelcfg.GetFilteredAttributesByPrefix(baseAttrs, mr.userAttribSelection, extraAttrs, MetricTypes)
	return attribute.NewSet(filteredAttrs...)
}

// spanMetricAttributes follow a given specification, so their attribute getters are predefined and can't be
// selected by the user
func (mr *MetricsReporter) spanMetricAttributes() []attributes.Field[*request.Span, attribute.KeyValue] {
	return append(attributes.OpenTelemetryGetters(
		mr.attrGetters, []attr.Name{
			attr.ServiceName,
			attr.ServiceInstanceID,
			attr.ServiceNamespace,
			attr.SpanKind,
			attr.SpanName,
			attr.StatusCode,
			attr.Source,
		}),
		// hostID is not taken from the span but common to the metrics reporter,
		// so the getter is injected here directly
		attributes.Field[*request.Span, attribute.KeyValue]{
			ExposedName: string(attr.HostID.OTEL()),
			Get: func(_ *request.Span) attribute.KeyValue {
				return semconv.HostID(mr.hostID)
			},
		})
}

func otelMetricsAccepted(span *request.Span, mr *MetricsReporter) bool {
	return mr.cfg.OTelMetricsEnabled() && !span.Service.ExportsOTelMetrics()
}

func otelSpanMetricsAccepted(span *request.Span, mr *MetricsReporter) bool {
	return mr.cfg.AnySpanMetricsEnabled() && !span.Service.ExportsOTelMetricsSpan()
}

//nolint:cyclop
func (r *Metrics) record(span *request.Span, mr *MetricsReporter) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()

	ctx := trace.ContextWithSpanContext(r.ctx, trace.SpanContext{}.WithTraceID(span.TraceID).WithSpanID(span.SpanID).WithTraceFlags(trace.TraceFlags(span.TraceFlags)))

	if otelMetricsAccepted(span, mr) {
		switch span.Type {
		case request.EventTypeHTTP:
			if mr.is.HTTPEnabled() {
				// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
				httpDuration, attrs := r.httpDuration.ForRecord(span)
				httpDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))

				httpRequestSize, attrs := r.httpRequestSize.ForRecord(span)
				httpRequestSize.Record(ctx, float64(span.RequestBodyLength()), instrument.WithAttributeSet(attrs))

				httpResponseSize, attrs := r.httpResponseSize.ForRecord(span)
				httpResponseSize.Record(ctx, float64(span.ResponseBodyLength()), instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeGRPC:
			if mr.is.GRPCEnabled() {
				grpcDuration, attrs := r.grpcDuration.ForRecord(span)
				grpcDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeGRPCClient:
			if mr.is.GRPCEnabled() {
				grpcClientDuration, attrs := r.grpcClientDuration.ForRecord(span)
				grpcClientDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeHTTPClient:
			if mr.is.HTTPEnabled() {
				httpClientDuration, attrs := r.httpClientDuration.ForRecord(span)
				httpClientDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
				httpClientRequestSize, attrs := r.httpClientRequestSize.ForRecord(span)
				httpClientRequestSize.Record(ctx, float64(span.RequestBodyLength()), instrument.WithAttributeSet(attrs))
				httpClientResponseSize, attrs := r.httpClientResponseSize.ForRecord(span)
				httpClientResponseSize.Record(ctx, float64(span.ResponseBodyLength()), instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeRedisServer, request.EventTypeRedisClient, request.EventTypeSQLClient, request.EventTypeMongoClient:
			if mr.is.DBEnabled() {
				dbClientDuration, attrs := r.dbClientDuration.ForRecord(span)
				dbClientDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeKafkaClient, request.EventTypeKafkaServer:
			if mr.is.MQEnabled() {
				switch span.Method {
				case request.MessagingPublish:
					msgPublishDuration, attrs := r.msgPublishDuration.ForRecord(span)
					msgPublishDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
				case request.MessagingProcess:
					msgProcessDuration, attrs := r.msgProcessDuration.ForRecord(span)
					msgProcessDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
				}
			}
		case request.EventTypeGPUKernelLaunch:
			if mr.is.GPUEnabled() {
				gcalls, attrs := r.gpuKernelCallsTotal.ForRecord(span)
				gcalls.Add(ctx, 1, instrument.WithAttributeSet(attrs))

				ggrid, attrs := r.gpuKernelGridSize.ForRecord(span)
				ggrid.Record(ctx, float64(span.ContentLength), instrument.WithAttributeSet(attrs))

				gblock, attrs := r.gpuKernelBlockSize.ForRecord(span)
				gblock.Record(ctx, float64(span.SubType), instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeGPUMalloc:
			if mr.is.GPUEnabled() {
				gmem, attrs := r.gpuMemoryAllocsTotal.ForRecord(span)
				gmem.Add(ctx, span.ContentLength, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeGPUMemcpy:
			if mr.is.GPUEnabled() {
				gmem, attrs := r.gpuMemoryCopySize.ForRecord(span)
				gmem.Record(r.ctx, float64(span.ContentLength), instrument.WithAttributeSet(attrs))
			}
		}
	}

	if otelSpanMetricsAccepted(span, mr) {
		if mr.cfg.SpanMetricsEnabled() {
			sml, attrs := r.spanMetricsLatency.ForRecord(span)
			sml.Record(ctx, duration, instrument.WithAttributeSet(attrs))

			smct, attrs := r.spanMetricsCallsTotal.ForRecord(span)
			smct.Add(ctx, 1, instrument.WithAttributeSet(attrs))
		}

		if mr.cfg.SpanMetricsSizesEnabled() {
			smst, attrs := r.spanMetricsRequestSizeTotal.ForRecord(span)
			smst.Add(ctx, float64(span.RequestBodyLength()), instrument.WithAttributeSet(attrs))

			smst, attr := r.spanMetricsResponseSizeTotal.ForRecord(span)
			smst.Add(ctx, float64(span.ResponseBodyLength()), instrument.WithAttributeSet(attr))
		}
	}
}

func (mr *MetricsReporter) createTargetInfo(attrs *attribute.Set) {
	mlog().Debug("Creating target_info")

	attrOpt := instrument.WithAttributeSet(*attrs)

	mr.targetInfo.Add(mr.ctx, 1, attrOpt)
}

func (mr *MetricsReporter) deleteTargetInfo(attrs *attribute.Set) {
	if attrs == nil {
		return
	}

	mlog().Debug("Deleting target_info for", "attrs", attrs)
	attrOpt := instrument.WithAttributeSet(*attrs)
	mr.targetInfo.Remove(mr.ctx, attrOpt)
}

func (mr *MetricsReporter) createTracesTargetInfo(attrs *attribute.Set) {
	if !mr.cfg.AnySpanMetricsEnabled() {
		return
	}

	mlog().Debug("Creating traces_target_info")

	attrOpt := instrument.WithAttributeSet(*attrs)

	mr.tracesTargetInfo.Add(mr.ctx, 1, attrOpt)
}

func (mr *MetricsReporter) deleteTracesTargetInfo(attrs *attribute.Set) {
	if attrs == nil || !mr.cfg.AnySpanMetricsEnabled() {
		return
	}

	mlog().Debug("Deleting traces_target_info for", "attrs", attrs)

	attrOpt := instrument.WithAttributeSet(*attrs)
	mr.tracesTargetInfo.Remove(mr.ctx, attrOpt)
}

func (mr *MetricsReporter) setupPIDToServiceRelationship(pid int32, uid svc.UID) {
	mr.pidTracker.AddPID(pid, uid)
}

func (mr *MetricsReporter) disassociatePIDFromService(pid int32) (bool, svc.UID) {
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

func (mr *MetricsReporter) resourceAttrsForService(service *svc.Attrs) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(string(attr.Instance), service.UID.Instance),
		attribute.String(string(attr.Job), service.Job()),
	}

	attrs = append(attrs, otelcfg.GetAppResourceAttrs(mr.hostID, service)...)
	return append(attrs, otelcfg.ResourceAttrsFromEnv(service)...)
}

func (mr *MetricsReporter) ensureTargetMetrics(service *svc.Attrs) *TargetMetrics {
	if service == nil {
		return nil
	}

	if targetMetrics, ok := mr.targetMetrics[service.UID]; ok {
		return targetMetrics
	}

	targetMetrics := &TargetMetrics{}

	targetMetrics.resourceAttributes = attribute.NewSet(mr.resourceAttrsForService(service)...)

	if mr.cfg.AnySpanMetricsEnabled() {
		targetMetrics.tracesResourceAttributes = mr.tracesResourceAttributes(service)
	} else {
		targetMetrics.tracesResourceAttributes = *attribute.EmptySet()
	}

	mr.targetMetrics[service.UID] = targetMetrics

	return targetMetrics
}

func (mr *MetricsReporter) createTargetMetricData(targetMetrics *TargetMetrics) {
	mr.createTargetInfo(&targetMetrics.resourceAttributes)
	mr.createTracesTargetInfo(&targetMetrics.tracesResourceAttributes)
}

func (mr *MetricsReporter) createTargetMetrics(service *svc.Attrs) {
	if service == nil {
		return
	}

	targetMetrics := mr.ensureTargetMetrics(service)

	if targetMetrics == nil {
		return
	}

	mr.createEventMetrics(targetMetrics)
}

func (mr *MetricsReporter) deleteTargetMetricData(targetMetrics *TargetMetrics) {
	mr.deleteTargetInfo(&targetMetrics.resourceAttributes)
	mr.deleteTracesTargetInfo(&targetMetrics.tracesResourceAttributes)
}

func (mr *MetricsReporter) deleteTargetMetrics(uid *svc.UID) {
	if uid == nil {
		return
	}

	targetMetrics, ok := mr.targetMetrics[*uid]

	if !ok {
		return
	}

	mr.deleteEventMetrics(targetMetrics)

	delete(mr.targetMetrics, *uid)
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
			mr.deleteTargetMetrics(&staleUID)
			mr.createTargetMetrics(&pe.File.Service)
			// we don't setup the pid again, we just replaced the metrics it's associated with
			return
		}

		// Handle the case when we have new labels for same service
		// It could be a brand new PID with this information, so we fall through after deleting
		// the old target info
		if _, ok := mr.targetMetrics[uid]; ok {
			mr.log.Debug("updating stale attributes for", "service", uid)
			mr.deleteTargetMetrics(&uid)
		}

		mr.createTargetMetrics(&pe.File.Service)
		mr.setupPIDToServiceRelationship(pe.File.Pid, pe.File.Service.UID)
	} else {
		if deleted, origUID := mr.disassociatePIDFromService(pe.File.Pid); deleted {
			// We only need the UID to look up in the pool, no need to cache
			// the whole of the attrs in the pidTracker
			mlog().Debug("deleting infos for", "pid", pe.File.Pid, "attrs", origUID)

			mr.deleteTargetMetrics(&origUID)

			if mr.cfg.HostMetricsEnabled() && mr.pidTracker.Count() == 0 {
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
		// If we are ignoring this span because of route patterns, don't do anything
		if request.IgnoreMetrics(s) {
			continue
		}
		reporter, err := mr.reporters.For(&s.Service)
		if err != nil {
			mlog().Error("unexpected error creating OTEL resource. Ignoring metric",
				"error", err, "service", s.Service)
			continue
		}
		reporter.record(s, mr)

		if mr.cfg.HostMetricsEnabled() {
			hostInfo, attrs := mr.hostInfo.ForRecord(s)
			hostInfo.Record(mr.ctx, 1, instrument.WithAttributeSet(attrs))
		}
	}
}

func cleanupMetrics(ctx context.Context, m *Expirer[*request.Span, instrument.Float64Histogram, float64]) {
	if m != nil {
		m.RemoveAllMetrics(ctx)
	}
}

func cleanupCounterMetrics(ctx context.Context, m *Expirer[*request.Span, instrument.Int64Counter, int64]) {
	if m != nil {
		m.RemoveAllMetrics(ctx)
	}
}

func cleanupFloatCounterMetrics(ctx context.Context, m *Expirer[*request.Span, instrument.Float64Counter, float64]) {
	if m != nil {
		m.RemoveAllMetrics(ctx)
	}
}

func (r *Metrics) cleanupAllMetricsInstances() {
	cleanupMetrics(r.ctx, r.httpDuration)
	cleanupMetrics(r.ctx, r.httpClientDuration)
	cleanupMetrics(r.ctx, r.grpcDuration)
	cleanupMetrics(r.ctx, r.grpcClientDuration)
	cleanupMetrics(r.ctx, r.dbClientDuration)
	cleanupMetrics(r.ctx, r.msgPublishDuration)
	cleanupMetrics(r.ctx, r.msgProcessDuration)
	cleanupMetrics(r.ctx, r.httpRequestSize)
	cleanupMetrics(r.ctx, r.httpResponseSize)
	cleanupMetrics(r.ctx, r.httpClientRequestSize)
	cleanupMetrics(r.ctx, r.spanMetricsLatency)
	cleanupCounterMetrics(r.ctx, r.spanMetricsCallsTotal)
	cleanupFloatCounterMetrics(r.ctx, r.spanMetricsRequestSizeTotal)
	cleanupFloatCounterMetrics(r.ctx, r.spanMetricsResponseSizeTotal)
	cleanupCounterMetrics(r.ctx, r.gpuKernelCallsTotal)
}
