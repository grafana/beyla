package export

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/castai/promwrite"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/prometheus/client_golang/prometheus"
)

// TODO: put here any exporter configuration

func mlog() *slog.Logger {
	return slog.With("component", "otel.MetricsReporter")
}

func metricValue(m map[string]interface{}) int {
	v, ok := m["Bytes"].(int)

	if !ok {
		return 0
	}

	return v
}

func labelValues(m map[string]interface{}) []string {
	res := make([]string, 0, 9)

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

	res = append(res, client)       // "client.name
	res = append(res, "test")       // "client.namespace
	res = append(res, "generator")  // "client.kind
	res = append(res, server)       // "server.name
	res = append(res, "test")       // "server.namespace
	res = append(res, "deployment") // "server.kind

	res = append(res, fmt.Sprint(serverPort)) // "server.port

	// probably not needed
	res = append(res, "dev")        // "asserts.env
	res = append(res, "beekeepers") // "asserts.site

	return res
}

func MetricsExporterProvider(cfg ExportConfig) (node.TerminalFunc[[]map[string]interface{}], error) {
	client := promwrite.NewClient(cfg.RemoteWriteURL)

	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_connections_observed",
		Help: "total bytes_sent value of connections observed by probe since its launch",
	}, []string{
		// need to keep the same order as labelValues returned attributes
		"client_name", "client_namespace", "client_kind", "server_name", "server_namespace",
		"server_kind", "server_port", "asserts_env", "asserts_site",
	})

	client.Write(context.TODO(), &promwrite.WriteRequest{
		TimeSeries: []promwrite.TimeSeries{{}},
	})

	return func(in <-chan []map[string]interface{}) {
		for i := range in {
			bytes, _ := json.Marshal(i)
			fmt.Println(string(bytes))

			for _, v := range i {
				counter.WithLabelValues(labelValues(v)...).Add(float64(metricValue(v)))
			}
		}
	}, nil
}
