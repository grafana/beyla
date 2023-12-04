package export

import (
	"context"
	"log/slog"
	"time"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/mariomac/pipes/pkg/node"
	otel2 "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
)

// TODO: put here any exporter configuration

func mlog() *slog.Logger {
	return slog.With("component", "otel.MetricsReporter")
}

func newResource() (*resource.Resource, error) {
	return resource.Merge(resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.21.0",
			semconv.ServiceName("beyla-network"),
			semconv.ServiceVersion("0.1.0"),
		))
}

func newMeterProvider(res *resource.Resource, exporter *metric.Exporter) (*metric.MeterProvider, error) {
	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter,
			// Default is 1m. Set to 3s for demonstrative purposes.
			metric.WithInterval(10*time.Second))),
	)
	return meterProvider, nil
}

func metricValue(m map[string]interface{}) int {
	v, ok := m["Bytes"].(int)

	if !ok {
		return 0
	}

	return v
}

func attributes(m map[string]interface{}) []attribute.KeyValue {
	res := make([]attribute.KeyValue, 0)

	v, ok := m["SrcAddr"].(string)

	if ok {
		res = append(res, attribute.String("client.name", v))
		res = append(res, attribute.String("client.namespace", "test"))
		res = append(res, attribute.String("client.kind", "generator"))
	}

	v, ok = m["DstAddr"].(string)

	if ok {
		res = append(res, attribute.String("server.name", v))
		res = append(res, attribute.String("server.namespace", "test"))
		res = append(res, attribute.String("server.kind", "deployment"))
	}

	direction := 2 // server
	serverPort, _ := m["DstPort"].(int)
	i, ok := m["FlowDirection"].(int)

	if ok {
		if i == 1 {
			direction = 1
		}
	}

	res = append(res, attribute.Int("server.port", serverPort))
	res = append(res, attribute.Int("role", direction))

	return res
}

func MetricsExporterProvider(cfg ExportConfig) (node.TerminalFunc[[]map[string]interface{}], error) {
	log := mlog()
	exporter, err := otel.InstantiateMetricsExporter(context.Background(), cfg.Metrics, log)
	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	resource, err := newResource()
	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	provider, err := newMeterProvider(resource, &exporter)

	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	otel2.SetMeterProvider(provider)

	ebpfEvents := otel2.Meter("ebpf_events")

	ebpfObserved, err := ebpfEvents.Int64Counter(
		"ebpf.connections.observed",
		metric2.WithDescription("total bytes_sent value of connections observed by probe since its launch"),
		metric2.WithUnit("{bytes}"),
	)

	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	return func(in <-chan []map[string]interface{}) {
		for i := range in {
			for _, v := range i {
				ebpfObserved.Add(
					context.Background(),
					int64(metricValue(v)),
					metric2.WithAttributes(attributes(v)...),
				)
			}
		}
	}, nil
}
