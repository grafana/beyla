package gpumetrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// PromConfig connects the GPU metrics to the existing Prometheus endpoint.
type PromConfig struct {
	Enabled   bool
	HostID    string
	HostName  string
	Register  func(prometheus.Collector) error
	StartHTTP func(context.Context)
}

type promCollector struct {
	source Source
	procs  *processes
	descs  map[*metricDef]*prometheus.Desc
}

func newPromCollector(cfg *PromConfig, source Source, procs *processes) *promCollector {
	constLabels := prometheus.Labels{hostID.Prom(): cfg.HostID, hostName.Prom(): cfg.HostName}
	descs := make(map[*metricDef]*prometheus.Desc, len(allMetrics))
	for _, def := range allMetrics {
		labels := make([]string, len(def.labels))
		for i, name := range def.labels {
			labels[i] = name.Prom()
		}
		descs[def] = prometheus.NewDesc(def.prom, def.help, labels, constLabels)
	}
	return &promCollector{source: source, procs: procs, descs: descs}
}

func (c *promCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range c.descs {
		ch <- desc
	}
}

func (c *promCollector) Collect(ch chan<- prometheus.Metric) {
	observe(c.source.Collect(), c.procs, func(def *metricDef, value float64, labelValues ...string) {
		valueType := prometheus.GaugeValue
		if def.kind == kindCounter {
			valueType = prometheus.CounterValue
		}
		ch <- prometheus.MustNewConstMetric(c.descs[def], valueType, value, labelValues...)
	})
}

// PromExport reports the GPU metrics in the Prometheus endpoint from a terminal pipeline node.
func PromExport(cfg PromConfig, source Source, events *msg.Queue[exec.ProcessEvent]) swarm.InstanceFunc {
	return func(context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled {
			return swarm.EmptyRunFunc()
		}
		procs := newProcesses()
		if err := cfg.Register(newPromCollector(&cfg, source, procs)); err != nil {
			return nil, err
		}
		watch := procs.watch(events, "gpumetrics.Prom")
		return func(ctx context.Context) {
			if cfg.StartHTTP != nil {
				go cfg.StartHTTP(ctx)
			}
			watch(ctx)
		}, nil
	}
}
