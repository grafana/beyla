package otel

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/attribute"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/attr"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/metricname"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/export"
)

type MetricsConfig struct {
	Metrics           *otel.MetricsConfig
	AllowedAttributes []string
}

func (mc MetricsConfig) Enabled() bool {
	return mc.Metrics != nil && mc.Metrics.EndpointEnabled() && slices.Contains(mc.Metrics.Features, otel.FeatureNetwork)
}

func mlog() *slog.Logger {
	return slog.With("component", "flows.MetricsReporter")
}

func newResource() *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceName("beyla-network-flows"),
		semconv.ServiceInstanceID(uuid.New().String()),
		// SpanMetrics requires an extra attribute besides service name
		// to generate the traces_target_info metric,
		// so the service is visible in the ServicesList
		// This attribute also allows that App O11y plugin shows this app as a Go application.
		semconv.TelemetrySDKLanguageKey.String(semconv.TelemetrySDKLanguageGo.Value.AsString()),
		// We set the SDK name as Beyla, so we can distinguish beyla generated metrics from other SDKs
		semconv.TelemetrySDKNameKey.String("beyla"),
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
}

func newMeterProvider(res *resource.Resource, exporter *metric.Exporter, interval time.Duration) (*metric.MeterProvider, error) {
	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter, metric.WithInterval(interval))),
	)
	return meterProvider, nil
}

type metricsExporter struct {
	metrics *Expirer
}

func MetricsExporterProvider(cfg *MetricsConfig) (pipe.FinalFunc[[]*ebpf.Record], error) {
	if !cfg.Enabled() {
		// This node is not going to be instantiated. Let the pipes library just ignore it.
		return pipe.IgnoreFinal[[]*ebpf.Record](), nil
	}
	log := mlog()
	log.Debug("instantiating network metrics exporter provider")
	exporter, err := otel.InstantiateMetricsExporter(context.Background(), cfg.Metrics, log)
	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	provider, err := newMeterProvider(newResource(), &exporter, cfg.Metrics.Interval)

	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	attrs := attr.OpenTelemetryGetters(export.NamedGetters, cfg.AllowedAttributes)
	if len(attrs) == 0 {
		return nil, fmt.Errorf("network metrics OpenTelemetry exporter: no valid"+
			" attributes.allow defined for metric %s", metricname.PromBeylaNetworkFlows)
	}
	expirer := NewExpirer(attrs, cfg.Metrics.TTL)
	ebpfEvents := provider.Meter("network_ebpf_events")

	_, err = ebpfEvents.Int64ObservableCounter(
		metricname.OTELBeylaNetworkFlows,
		metric2.WithDescription("total bytes_sent value of network flows observed by probe since its launch"),
		metric2.WithUnit("{bytes}"),
		metric2.WithInt64Callback(expirer.Collect),
	)
	if err != nil {
		log.Error("creating observable counter", "error", err)
		return nil, err
	}
	log.Debug("restricting attributes not in this list", "attributes", cfg.AllowedAttributes)
	return (&metricsExporter{
		metrics: expirer,
	}).Do, nil
}

func (me *metricsExporter) Do(in <-chan []*ebpf.Record) {
	for i := range in {
		me.metrics.UpdateTime()
		for _, v := range i {
			me.metrics.ForRecord(v).val.Add(int64(v.Metrics.Bytes))
		}
	}
}
