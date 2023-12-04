package export

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/mariomac/pipes/pkg/node"
	otel2 "go.opentelemetry.io/otel"
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
		resource.NewWithAttributes(semconv.SchemaURL,
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

func MetricsExporterProvider(cfg otel.MetricsConfig) (node.TerminalFunc[[]map[string]interface{}], error) {
	log := mlog()
	exporter, err := otel.InstantiateMetricsExporter(context.Background(), &cfg, log)
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

	fmt.Printf("aaa %v", ebpfObserved)

	return func(in <-chan []map[string]interface{}) {
		for i := range in {

			// TODO: replace by something more useful
			bytes, _ := json.Marshal(i)
			fmt.Println(string(bytes))
		}
	}, nil
}
