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
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// PrometheusConfig for network metrics just wrap the global prom.PrometheusConfig as provided by the user
type PrometheusConfig struct {
	Config            *prom.PrometheusConfig
	AllowedAttributes []string
}

// nolint:gocritic
func (p PrometheusConfig) Enabled() bool {
	return p.Config != nil && p.Config.Port != 0 && slices.Contains(p.Config.Features, otel.FeatureNetwork)
}

type metricsReporter struct {
	cfg *prom.PrometheusConfig

	flowBytes *prometheus.CounterVec

	promConnect *connector.PrometheusManager

	attrs []export.Attribute

	bgCtx   context.Context
	ctxInfo *global.ContextInfo
}

func PrometheusEndpoint(ctx context.Context, cfg *PrometheusConfig, ctxInfo *global.ContextInfo) (node.TerminalFunc[[]*ebpf.Record], error) {
	reporter := newReporter(ctx, cfg, ctxInfo)
	return reporter.reportMetrics, nil
}

func newReporter(ctx context.Context, cfg *PrometheusConfig, ctxInfo *global.ContextInfo) *metricsReporter {
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &metricsReporter{
		bgCtx:       ctx,
		ctxInfo:     ctxInfo,
		cfg:         cfg.Config,
		promConnect: ctxInfo.Prometheus,
		attrs:       export.BuildPromAttributeGetters(cfg.AllowedAttributes),
		flowBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "beyla_network_flow_bytes",
			Help: "bytes submitted from a source network endpoint to a destination network endpoint",
		}, cfg.AllowedAttributes),
	}

	mr.promConnect.Register(cfg.Config.Port, cfg.Config.Path, mr.flowBytes)

	return mr
}

func (r *metricsReporter) reportMetrics(input <-chan []*ebpf.Record) {
	go r.promConnect.StartHTTP(r.bgCtx)
	for flows := range input {
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
