package prom

import (
	"context"
	"slices"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/export/prom"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/export"
)

// PrometheusConfig for network metrics just wraps the global prom.PrometheusConfig as provided by the user
type PrometheusConfig struct {
	Config            *prom.PrometheusConfig
	AllowedAttributes []string
}

// nolint:gocritic
func (p PrometheusConfig) Enabled() bool {
	return p.Config != nil && p.Config.Port != 0 && slices.Contains(p.Config.Features, otel.FeatureNetwork)
}

type counterCollector interface {
	prometheus.Collector
	UpdateTime()
	WithLabelValues(...string) prometheus.Counter
}

type metricsReporter struct {
	cfg *prom.PrometheusConfig

	flowBytes counterCollector

	promConnect *connector.PrometheusManager

	attrs []export.Attribute

	bgCtx context.Context
}

func PrometheusEndpoint(ctx context.Context, cfg *PrometheusConfig, promMgr *connector.PrometheusManager) (node.TerminalFunc[[]*ebpf.Record], error) {
	reporter := newReporter(ctx, cfg, promMgr)
	return reporter.reportMetrics, nil
}

func newReporter(ctx context.Context, cfg *PrometheusConfig, promMgr *connector.PrometheusManager) *metricsReporter {
	attrs := export.BuildPromAttributeGetters(cfg.AllowedAttributes)
	labelNames := make([]string, 0, len(attrs))
	for _, label := range attrs {
		labelNames = append(labelNames, label.Name)
	}

	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &metricsReporter{
		bgCtx:       ctx,
		cfg:         cfg.Config,
		promConnect: promMgr,
		attrs:       attrs,
		flowBytes: NewExpirer(prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "beyla_network_flow_bytes_total",
			Help: "bytes submitted from a source network endpoint to a destination network endpoint",
		}, labelNames), cfg.Config.ExpireTime),
	}

	mr.promConnect.Register(cfg.Config.Port, cfg.Config.Path, mr.flowBytes)

	return mr
}

func (r *metricsReporter) reportMetrics(input <-chan []*ebpf.Record) {
	go r.promConnect.StartHTTP(r.bgCtx)
	for flows := range input {
		r.flowBytes.UpdateTime()
		for _, flow := range flows {
			r.observe(flow)
		}
	}
}

func (r *metricsReporter) observe(flow *ebpf.Record) {
	labelValues := make([]string, 0, len(r.attrs))
	for _, attr := range r.attrs {
		labelValues = append(labelValues, attr.Get(flow))
	}
	r.flowBytes.WithLabelValues(labelValues...).Add(float64(flow.Metrics.Bytes))
}
