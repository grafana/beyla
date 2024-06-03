package prom

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/mariomac/pipes/pipe"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/expire"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/export/prom"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// injectable function reference for testing
var timeNow = time.Now

// PrometheusConfig for network metrics just wraps the global prom.PrometheusConfig as provided by the user
type PrometheusConfig struct {
	Config             *prom.PrometheusConfig
	AttributeSelectors attributes.Selection
}

// nolint:gocritic
func (p PrometheusConfig) Enabled() bool {
	return p.Config != nil && p.Config.Port != 0 && slices.Contains(p.Config.Features, otel.FeatureNetwork)
}

type counterCollector interface {
	prometheus.Collector
	WithLabelValues(...string) prometheus.Counter
}

type metricsReporter struct {
	cfg *prom.PrometheusConfig

	flowBytes counterCollector

	promConnect *connector.PrometheusManager

	attrs []attributes.Field[*ebpf.Record, string]

	clock *expire.CachedClock
	bgCtx context.Context
}

func PrometheusEndpoint(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
) (pipe.FinalFunc[[]*ebpf.Record], error) {
	if !cfg.Enabled() {
		// This node is not going to be instantiated. Let the pipes library just ignore it.
		return pipe.IgnoreFinal[[]*ebpf.Record](), nil
	}
	reporter, err := newReporter(ctx, ctxInfo, cfg)
	if err != nil {
		return nil, err
	}
	return reporter.reportMetrics, nil
}

func newReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
) (*metricsReporter, error) {
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
	mr := &metricsReporter{
		bgCtx:       ctx,
		cfg:         cfg.Config,
		promConnect: ctxInfo.Prometheus,
		attrs:       attrs,
		clock:       clock,
		flowBytes: expire.NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.BeylaNetworkFlow.Prom,
			Help: "bytes submitted from a source network endpoint to a destination network endpoint",
		}, labelNames).MetricVec, clock.Time, cfg.Config.TTL),
	}

	mr.promConnect.Register(cfg.Config.Port, cfg.Config.Path, mr.flowBytes)

	return mr, nil
}

func (r *metricsReporter) reportMetrics(input <-chan []*ebpf.Record) {
	go r.promConnect.StartHTTP(r.bgCtx)
	for flows := range input {
		// clock needs to be updated to let the expirer
		// remove the old metrics
		r.clock.Update()
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
