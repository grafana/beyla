package otel

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/attribute"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/otel"
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

func newMeterProvider(res *resource.Resource, exporter *metric.Exporter) (*metric.MeterProvider, error) {
	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter,
			// Default is 1m. Set to 3s for demonstrative purposes.
			metric.WithInterval(1*time.Second))),
	)
	return meterProvider, nil
}

type metricsExporter struct {
	flowBytes metric2.Int64Counter
	attrs     []export.Attribute
}

func (me *metricsExporter) attributes(m *ebpf.Record) []attribute.KeyValue {
	keyVals := make([]attribute.KeyValue, 0, len(me.attrs))

	for _, attr := range me.attrs {
		keyVals = append(keyVals,
			attribute.String(attr.Name, attr.Get(m)))
	}

	return keyVals
}

func MetricsExporterProvider(cfg MetricsConfig) (node.TerminalFunc[[]*ebpf.Record], error) {
	log := mlog()
	log.Debug("instantiating network metrics exporter provider")
	exporter, err := otel.InstantiateMetricsExporter(context.Background(), cfg.Metrics, log)
	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	provider, err := newMeterProvider(newResource(), &exporter)

	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	ebpfEvents := provider.Meter("network_ebpf_events")

	flowBytes, err := ebpfEvents.Int64Counter(
		"beyla.network.flow.bytes",
		metric2.WithDescription("total bytes_sent value of network flows observed by probe since its launch"),
		metric2.WithUnit("{bytes}"),
	)
	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}
	log.Debug("restricting attributes not in this list", "attributes", cfg.AllowedAttributes)
	return (&metricsExporter{
		flowBytes: flowBytes,
		attrs:     export.BuildOTELAttributeGetters(cfg.AllowedAttributes),
	}).Do, nil
}

func (me *metricsExporter) Do(in <-chan []*ebpf.Record) {
	for i := range in {
		for _, v := range i {
			me.flowBytes.Add(
				context.Background(),
				int64(v.Metrics.Bytes),
				metric2.WithAttributes(me.attributes(v)...),
			)
		}
	}
}
