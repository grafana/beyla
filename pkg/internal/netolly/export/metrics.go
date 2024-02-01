package export

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	otel2 "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/otel"
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

func mapStr(m map[string]interface{}, key string) (string, bool) {
	if val, ok := m[key]; ok {
		return val.(string), true
	}
	return "", false
}

func sourceAttrs(m map[string]interface{}) (namespace, name string) {
	if srcName, ok := mapStr(m, "SrcK8s_Name"); ok && srcName != "" {
		srcNS, _ := mapStr(m, "SrcK8s_Namespace")
		return srcNS, srcName
	}
	srcName, _ := mapStr(m, "SrcAddr")
	return "", srcName
}

func destinationAttrs(m map[string]interface{}) (namespace, name, kind string) {
	kind, _ = mapStr(m, "DstK8s_Kind")
	if dstName, ok := mapStr(m, "DstK8s_Name"); ok && dstName != "" {
		dstNs, _ := mapStr(m, "DstK8s_Namespace")
		return dstNs, dstName, kind
	}
	dstName, _ := mapStr(m, "DstAddr")
	return "", dstName, kind
}

func direction(m map[string]interface{}) string {
	if dir, ok := m["FlowDirection"]; ok {
		if dirInt, ok := dir.(int); ok {
			switch dirInt {
			case 0:
				return "ingress"
			case 1:
				return "egress"
			}
		}
	}
	return "unknown"
}

func attributes(m map[string]interface{}) []attribute.KeyValue {
	res := make([]attribute.KeyValue, 0)

	serverPort, _ := m["DstPort"].(int)
	srcNS, srcName := sourceAttrs(m)
	dstNS, dstName, dstKind := destinationAttrs(m)

	res = append(res, attribute.String("flow.direction", direction(m)))
	res = append(res, attribute.Int("server.port", serverPort))
	res = append(res, attribute.String("src.name", srcName))
	res = append(res, attribute.String("src.namespace", srcNS))
	res = append(res, attribute.String("dst.name", dstName))
	res = append(res, attribute.String("dst.namespace", dstNS))
	res = append(res, attribute.String("dst.kind", dstKind))

	// probably not needed
	res = append(res, attribute.String("asserts.env", "dev"))
	res = append(res, attribute.String("asserts.site", "dev"))

	return res
}

func strAttr(m map[string]interface{}, name string) string {
	v, ok := m[name].(string)
	if !ok {
		return ""
	}

	return v
}

func agentMetric(m map[string]interface{}) bool {
	agentIP := strAttr(m, "AgentIP")

	if agentIP != "" {
		src := strAttr(m, "SrcAddr")
		dst := strAttr(m, "DstAddr")

		return src == agentIP || dst == agentIP
	}

	return false
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

	return func(in <-chan []map[string]interface{}) {
		for i := range in {
			bytes, err := json.Marshal(i)
			if err != nil {
				log.Error("can't marshall JSON flows", "error", err)
			} else {
				log.Info("sending flows", "len", len(i))
				fmt.Println(string(bytes))
			}

			for _, v := range i {
				// Don't report metrics for the agent itself
				// TODO: make configurable, as the agent flow metrics are ok
				//if agentMetric(v)  {
				//	continue
				//}

				flowBytes.Add(
					context.Background(),
					int64(metricValue(v)),
					metric2.WithAttributes(attributes(v)...),
				)
			}
		}
	}, nil
}
