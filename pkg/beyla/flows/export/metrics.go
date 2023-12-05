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

	direction, _ := m["FlowDirection"].(int) // not used, they rely on client<->server
	serverPort := 0
	if direction == 0 {
		serverPort, _ = m["SrcPort"].(int)
	} else {
		serverPort, _ = m["DstPort"].(int)
	}

	client, ok := m["SrcHost"].(string)

	if !ok {
		client, _ = m["SrcAddr"].(string)
	}

	server, ok := m["DstHost"].(string)

	if !ok {
		server, _ = m["DstAddr"].(string)
	}

	if direction == 0 {
		tmp := server
		server = client
		client = tmp
	}

	res = append(res, attribute.String("client.name", client))
	res = append(res, attribute.String("client.namespace", "test"))
	res = append(res, attribute.String("client.kind", "generator"))
	res = append(res, attribute.String("server.name", server))
	res = append(res, attribute.String("server.namespace", "test"))
	res = append(res, attribute.String("server.kind", "deployment"))

	res = append(res, attribute.Int("server.port", serverPort))

	// probably not needed
	res = append(res, attribute.String("asserts.env", "dev"))
	res = append(res, attribute.String("asserts.site", "beekeepers"))

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
			bytes, _ := json.Marshal(i)
			fmt.Println(string(bytes))

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
