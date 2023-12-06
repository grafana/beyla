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

func clientK8SField(field string, m map[string]interface{}, direction int) string {
	if direction == 1 { // client
		v, ok := m["SrcK8s_"+field].(string)

		if !ok {
			return ""
		}
		return v
	}

	v, ok := m["DstK8s_"+field].(string)

	if !ok {
		return ""
	}
	return v
}

func clientNamespace(m map[string]interface{}, direction int) string {
	return clientK8SField("Namespace", m, direction)
}

func clientKind(m map[string]interface{}, direction int) string {
	kind := clientK8SField("Type", m, direction)
	if kind == "" {
		kind = "external"
	}

	return kind
}

func clientName(m map[string]interface{}, direction int) string {
	name := clientK8SField("Name", m, direction)
	if name == "" {
		if direction == 1 { // client
			v, ok := m["SrcHost"].(string)
			if !ok {
				v, _ = m["SrcAddr"].(string)
			}
			name = v
		} else {
			v, ok := m["DstHost"].(string)
			if !ok {
				v, _ = m["DstAddr"].(string)
			}
			name = v
		}
	}

	return name
}

func attributes(m map[string]interface{}) []attribute.KeyValue {
	res := make([]attribute.KeyValue, 0)

	oppositeDirection := 1
	direction, _ := m["FlowDirection"].(int) // not used, they rely on client<->server
	serverPort, _ := m["SrcPort"].(int)
	destPort, _ := m["DstPort"].(int)

	if direction == 1 {
		oppositeDirection = 0
	}

	if destPort < serverPort {
		serverPort = destPort
		if direction == 0 {
			direction = 1
			oppositeDirection = 0
		} else {
			direction = 0
			oppositeDirection = 1
		}
	}

	res = append(res, attribute.String("client.name", clientName(m, direction)))
	res = append(res, attribute.String("client.namespace", clientNamespace(m, direction)))
	res = append(res, attribute.String("client.kind", clientKind(m, direction)))
	res = append(res, attribute.String("server.name", clientName(m, oppositeDirection)))
	res = append(res, attribute.String("server.namespace", clientNamespace(m, oppositeDirection)))
	res = append(res, attribute.String("server.kind", clientKind(m, oppositeDirection)))

	res = append(res, attribute.Int("server.port", serverPort))

	// probably not needed
	res = append(res, attribute.String("asserts.env", "dev"))
	res = append(res, attribute.String("asserts.site", "beekeepers"))

	return res
}

func processEvents(i []map[string]interface{}) {
	bytes, _ := json.Marshal(i)
	fmt.Println(string(bytes))

	for _, v := range i {
		fmt.Println(attributes(v))
	}
}

func strAttr(m map[string]interface{}, name string) string {
	v, ok := m[name].(string)
	if !ok {
		return ""
	}

	return v
}

func intAttr(m map[string]interface{}, name string) int {
	v, ok := m[name].(int)
	if !ok {
		return 0
	}

	return v
}

func eitherOr(first, second string) string {
	if first != "" {
		return first
	}

	return second
}

func flowAttributes(m map[string]interface{}) []attribute.KeyValue {
	res := make([]attribute.KeyValue, 0)

	res = append(res, attribute.String("src.ip", strAttr(m, "SrcAddr")))
	res = append(res, attribute.String("src.host", eitherOr(strAttr(m, "SrcK8s_Name"), strAttr(m, "SrcHost"))))
	res = append(res, attribute.String("src.namespace", strAttr(m, "SrcK8s_Namespace")))
	res = append(res, attribute.String("src.type", strAttr(m, "SrcK8s_Type")))
	res = append(res, attribute.String("src.node.ip", strAttr(m, "SrcK8s_HostIP")))

	srcPort := intAttr(m, "SrcPort")
	if srcPort > 32768 {
		srcPort = 0
	}
	res = append(res, attribute.Int("src.port", srcPort))

	res = append(res, attribute.Int("direction", intAttr(m, "FlowDirection")))

	proto := intAttr(m, "Proto")
	protocol := ""
	if proto == 6 {
		protocol = "TCP"
	} else if proto == 17 {
		protocol = "UDP"
	}

	res = append(res, attribute.String("protocol", protocol))
	res = append(res, attribute.String("inteface", strAttr(m, "Interface")))

	res = append(res, attribute.String("dst.ip", strAttr(m, "DstAddr")))
	res = append(res, attribute.String("dst.host", eitherOr(strAttr(m, "DstK8s_Name"), strAttr(m, "SrcHost"))))
	res = append(res, attribute.String("dst.namespace", strAttr(m, "DstK8s_Namespace")))
	res = append(res, attribute.String("dst.type", strAttr(m, "DstK8s_Type")))
	res = append(res, attribute.String("dst.node.ip", strAttr(m, "DstK8s_HostIP")))

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

	flowsBytes, err := ebpfEvents.Int64Counter(
		"ebpf.flows.observed",
		metric2.WithDescription("total bytes_sent value of connections observed by probe since its launch"),
		metric2.WithUnit("{bytes}"),
	)
	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	flowsPackets, err := ebpfEvents.Int64Counter(
		"ebpf.flows.observed.packets",
		metric2.WithDescription("total packets_sent value of connections observed by probe since its launch"),
		metric2.WithUnit("{packets}"),
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
				flowsBytes.Add(
					context.Background(),
					int64(metricValue(v)),
					metric2.WithAttributes(flowAttributes(v)...),
				)
				flowsPackets.Add(
					context.Background(),
					int64(intAttr(v, "Packets")),
					metric2.WithAttributes(flowAttributes(v)...),
				)
			}
		}
	}, nil
}
