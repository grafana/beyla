package export

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/castai/promwrite"
	"github.com/mariomac/pipes/pkg/node"
)

// TODO: make configurable
const metricsEvictionPeriod = time.Minute

func mlog() *slog.Logger {
	return slog.With("component", "export.MetricsExporterProvider")
}

func metricValue(m map[string]interface{}) int {
	v, ok := m["Bytes"].(int)

	if !ok {
		return 0
	}

	return v
}

type labelSet [9]promwrite.Label

func metricLabels(m map[string]interface{}) labelSet {
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

	return labelSet{
		{Name: "client_name", Value: client},
		{Name: "client_namespace", Value: "test"},
		{Name: "client_kind", Value: "generator"},
		{Name: "server_name", Value: server},
		{Name: "server_namespace", Value: "test"},
		{Name: "server_kind", Value: "deployment"},
		{Name: "server_port", Value: strconv.Itoa(serverPort)},
		// probably not needed
		{Name: "asserts_env", Value: "dev"},
		{Name: "asserts_site", Value: "beekeepers"},
	}
}

func MetricsExporterProvider(cfg ExportConfig) (node.TerminalFunc[[]map[string]interface{}], error) {
	return func(in <-chan []map[string]interface{}) {
		mr := metricsExporter{
			log:      mlog(),
			client:   promwrite.NewClient(cfg.RemoteWriteURL),
			counters: map[labelSet]*promwrite.Sample{},
		}

		evictTicker := time.NewTicker(metricsEvictionPeriod)
		submitTicker := time.NewTicker(cfg.RemoteWritePeriod)
		for {
			// handling all the cases from the same goroutine prevents us from implementing
			// synchronization mechanisms
			select {
			case <-evictTicker.C:
				mr.cleanupOldMetrics()
			case <-submitTicker.C:
				// submit metrics!
				mr.remoteWrite()
				submitTicker.Reset(cfg.RemoteWritePeriod)
			case metrics, ok := <-in:
				if !ok {
					mr.log.Info("stopping metrics exporter loop")
					return
				}
				for _, v := range metrics {
					mr.account(v)
				}

			}
		}
	}, nil
}

type metricsExporter struct {
	log      *slog.Logger
	client   *promwrite.Client
	counters map[labelSet]*promwrite.Sample
}

// TODO: expire old connections
func (m *metricsExporter) account(metric map[string]interface{}) {
	ls := metricLabels(metric)
	bytes := metricValue(metric)

	counter, ok := m.counters[ls]
	if !ok {
		counter = &promwrite.Sample{}
		m.counters[ls] = counter
	}
	counter.Time = time.Now()
	counter.Value += float64(bytes)
}

func (m *metricsExporter) remoteWrite() {
	series := make([]promwrite.TimeSeries, 0, len(m.counters))
	for ls, val := range m.counters {
		series = append(series, promwrite.TimeSeries{
			Labels: ls[:],
			Sample: *val,
		})
	}
	wr, err := m.client.Write(context.TODO(), &promwrite.WriteRequest{TimeSeries: series})
	if err != nil {
		m.log.Error("can't write metrics", "error", err)
	} else {
		m.log.Debug("remote write succeeded", "response", *wr)
	}
}

func (m *metricsExporter) cleanupOldMetrics() {
	now := time.Now()
	for k, v := range m.counters {
		if v.Time.Sub(now) > metricsEvictionPeriod {
			delete(m.counters, k)
		}
	}
}
