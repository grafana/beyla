package export

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/mariomac/pipes/pkg/node"
	otel2 "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

const (
	// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
	directionIngress = 0
	directionEgress  = 1
)

type MetricsConfig struct {
	Metrics *otel.MetricsConfig
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

func attributes(m *ebpf.Record) []attribute.KeyValue {
	res := make([]attribute.KeyValue, 0, 11+len(m.Attrs.Metadata))

	res = append(res,
		attribute.String("beyla.ip", m.Attrs.BeylaIP),
		attribute.String("iface", m.Attrs.Interface),
		attribute.String("direction", directionStr(m.Id.Direction)),
		attribute.String("src.address", m.Id.SrcIP().IP().String()),
		attribute.String("dst.address", m.Id.DstIP().IP().String()),
		attribute.String("src.name", m.Attrs.SrcName),
		attribute.String("src.namespace", m.Attrs.SrcNamespace),
		attribute.String("dst.name", m.Attrs.DstName),
		attribute.String("dst.namespace", m.Attrs.DstNamespace),
	)

	// metadata attributes
	for k, v := range m.Attrs.Metadata {
		res = append(res, attribute.String(k, v))
	}

	return res
}

func directionStr(direction uint8) string {
	switch direction {
	case directionIngress:
		return "ingress"
	case directionEgress:
		return "egress"
	}
	// should never happen
	return "unknown"
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

	otel2.SetMeterProvider(provider)

	ebpfEvents := otel2.Meter("network_ebpf_events")

	flowBytes, err := ebpfEvents.Int64Counter(
		"network.flow.bytes",
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

	return func(in <-chan []*ebpf.Record) {
		for i := range in {
			for _, v := range i {
				flowBytes.Add(
					context.Background(),
					int64(v.Metrics.Bytes),
					metric2.WithAttributes(attributes(v)...),
				)
			}
		}
	}, nil
}
