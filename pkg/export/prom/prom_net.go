package prom

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pipe"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	"github.com/grafana/beyla/v2/pkg/export/expire"
	"github.com/grafana/beyla/v2/pkg/internal/connector"
	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
)

// injectable function reference for testing

// NetPrometheusConfig for network metrics just wraps the global prom.NetPrometheusConfig as provided by the user
type NetPrometheusConfig struct {
	Config             *PrometheusConfig
	AttributeSelectors attributes.Selection
	GloballyEnabled    bool
}

// nolint:gocritic
func (p NetPrometheusConfig) Enabled() bool {
	return p.Config != nil && p.Config.EndpointEnabled() && (p.Config.NetworkMetricsEnabled() || p.GloballyEnabled)
}

type netMetricsReporter struct {
	cfg *PrometheusConfig

	flowBytes *Expirer[prometheus.Counter]

	promConnect *connector.PrometheusManager

	attrs []attributes.Field[*ebpf.Record, string]

	clock *expire.CachedClock
	bgCtx context.Context
}

func NetPrometheusEndpoint(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *NetPrometheusConfig,
) (pipe.FinalFunc[[]*ebpf.Record], error) {
	if !cfg.Enabled() {
		// This node is not going to be instantiated. Let the pipes library just ignore it.
		return pipe.IgnoreFinal[[]*ebpf.Record](), nil
	}
	reporter, err := newNetReporter(ctx, ctxInfo, cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Config.Registry != nil {
		return reporter.collectMetrics, nil
	}
	return reporter.reportMetrics, nil
}

func newNetReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *NetPrometheusConfig,
) (*netMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.AttributeSelectors)
	if err != nil {
		return nil, fmt.Errorf("network Prometheus exporter attributes enable: %w", err)
	}

	attrs := attributes.PrometheusGetters(
		ebpf.RecordStringGetters,
		provider.For(attributes.BeylaNetworkFlow))

	labelNames := make([]string, 0, len(attrs))
	for _, label := range attrs {
		labelNames = append(labelNames, label.ExposedName)
	}

	clock := expire.NewCachedClock(timeNow)
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &netMetricsReporter{
		bgCtx:       ctx,
		cfg:         cfg.Config,
		promConnect: ctxInfo.Prometheus,
		attrs:       attrs,
		clock:       clock,
		flowBytes: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.BeylaNetworkFlow.Prom,
			Help: "bytes submitted from a source network endpoint to a destination network endpoint",
		}, labelNames).MetricVec, clock.Time, cfg.Config.TTL),
	}
	if cfg.Config.Registry != nil {
		cfg.Config.Registry.MustRegister(mr.flowBytes)
	} else {
		mr.promConnect.Register(cfg.Config.Port, cfg.Config.Path, mr.flowBytes)
	}

	return mr, nil
}

func (r *netMetricsReporter) reportMetrics(input <-chan []*ebpf.Record) {
	go r.promConnect.StartHTTP(r.bgCtx)
	r.collectMetrics(input)
}

func (r *netMetricsReporter) collectMetrics(input <-chan []*ebpf.Record) {
	for flows := range input {
		// clock needs to be updated to let the expirer
		// remove the old metrics
		r.clock.Update()
		for _, flow := range flows {
			r.observe(flow)
		}
	}
}

func (r *netMetricsReporter) observe(flow *ebpf.Record) {
	labelValues := make([]string, 0, len(r.attrs))
	for _, attr := range r.attrs {
		labelValues = append(labelValues, attr.Get(flow))
	}
	r.flowBytes.WithLabelValues(labelValues...).metric.Add(float64(flow.Metrics.Bytes))
}
