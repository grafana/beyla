package prom

import (
	"context"
	"fmt"
	"slices"

	"github.com/mariomac/pipes/pipe"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/expire"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// injectable function reference for testing

// ProcPrometheusConfig for process metrics just wraps the global prom.ProcPrometheusConfig as provided by the user
type ProcPrometheusConfig struct {
	Metrics            *PrometheusConfig
	AttributeSelectors attributes.Selection
}

// nolint:gocritic
func (p ProcPrometheusConfig) Enabled() bool {
	// TODO:
	return p.Metrics != nil && p.Metrics.Port != 0 && p.Metrics.OTelMetricsEnabled() &&
		slices.Contains(p.Metrics.Features, otel.FeatureProcess)
}

// ProcPrometheusEndpoint provides a pipeline node that export the process information as
// prometheus metrics
func ProcPrometheusEndpoint(
	ctx context.Context, ctxInfo *global.ContextInfo, cfg *ProcPrometheusConfig,
) pipe.FinalProvider[[]*process.Status] {
	return func() (pipe.FinalFunc[[]*process.Status], error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the pipes library just ignore it.
			return pipe.IgnoreFinal[[]*process.Status](), nil
		}
		reporter, err := newProcReporter(ctx, ctxInfo, cfg)
		if err != nil {
			return nil, err
		}
		return reporter.reportMetrics, nil
	}
}

type procMetricsReporter struct {
	cfg *PrometheusConfig

	promConnect *connector.PrometheusManager

	attrs []attributes.Field[*process.Status, string]

	clock *expire.CachedClock
	bgCtx context.Context

	// metrics
	cpuTime        *Expirer[prometheus.Counter]
	cpuUtilization *Expirer[prometheus.Gauge]
}

func newProcReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *ProcPrometheusConfig,
) (*procMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.AttributeSelectors)
	if err != nil {
		return nil, fmt.Errorf("network Prometheus exporter attributes enable: %w", err)
	}

	attrs := attributes.PrometheusGetters(
		process.PromGetters,
		provider.For(attributes.ProcessCPUUtilization))

	labelNames := make([]string, 0, len(attrs))
	for _, label := range attrs {
		labelNames = append(labelNames, label.ExposedName)
	}

	clock := expire.NewCachedClock(timeNow)
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &procMetricsReporter{
		bgCtx:       ctx,
		cfg:         cfg.Metrics,
		promConnect: ctxInfo.Prometheus,
		attrs:       attrs,
		clock:       clock,
		cpuUtilization: NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.ProcessCPUUtilization.Prom,
			Help: "Difference in process.cpu.time since the last measurement, divided by the elapsed time and number of CPUs available to the process",
		}, labelNames).MetricVec, clock.Time, cfg.Metrics.TTL),
	}

	mr.promConnect.Register(cfg.Metrics.Port, cfg.Metrics.Path, mr.cpuUtilization)

	return mr, nil
}

func (r *procMetricsReporter) reportMetrics(input <-chan []*process.Status) {
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

func (r *procMetricsReporter) observe(flow *process.Status) {
	labelValues := make([]string, 0, len(r.attrs))
	for _, attr := range r.attrs {
		labelValues = append(labelValues, attr.Get(flow))
	}
	r.cpuTime.WithLabelValues(labelValues...).Add(flow.CPUTimeUserDelta)
	r.cpuUtilization.WithLabelValues(labelValues...).Set(flow.CPUUtilisationUser)
	// TODO here user/system/wait
}
