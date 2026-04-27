// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// injectable function reference for testing

// StatsPrometheusConfig for stat metrics just wraps the global prom.StatsPrometheusConfig as provided by the user
type StatsPrometheusConfig struct {
	Config      *PrometheusConfig
	SelectorCfg *attributes.SelectorConfig
	CommonCfg   *perapp.MetricsConfig
}

// Enabled returns whether the node needs to be activated
func (p StatsPrometheusConfig) Enabled() bool {
	return p.Config != nil && p.Config.EndpointEnabled() && (p.CommonCfg.Features.StatMetrics())
}

type statMetricsReporter struct {
	cfg *PrometheusConfig

	tcpRtt *Expirer[prometheus.Histogram]

	tcpFailedConnections *Expirer[prometheus.Counter]

	promConnect *connector.PrometheusManager

	tcpRttAttrs               []attributes.Field[*ebpf.Stat, string]
	tcpFailedConnectionsAttrs []attributes.Field[*ebpf.Stat, string]

	clock *expire.CachedClock

	input <-chan []*ebpf.Stat
}

func StatsPrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *StatsPrometheusConfig,
	input *msg.Queue[[]*ebpf.Stat],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the swarm library just ignore it.
			return swarm.EmptyRunFunc()
		}
		reporter, err := newStatsReporter(ctxInfo, cfg, input)
		if err != nil {
			return nil, err
		}
		if cfg.Config.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

func newStatsReporter(
	ctxInfo *global.ContextInfo,
	cfg *StatsPrometheusConfig,
	input *msg.Queue[[]*ebpf.Stat],
) (*statMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("stats Prometheus exporter attributes enable: %w", err)
	}

	clock := expire.NewCachedClock(timeNow)
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &statMetricsReporter{
		cfg:         cfg.Config,
		promConnect: ctxInfo.Prometheus,
		clock:       clock,
	}

	var register []prometheus.Collector
	log := slog.With("component", "prom.StatsEndpoint")
	if cfg.CommonCfg.Features.StatsTCPRtt() {
		log.Debug("registering stat tcp rtt metric")

		mr.tcpRttAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPRtt))

		mr.tcpRtt = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: attributes.StatTCPRtt.Prom,
			Help: "measures the smoothed TCP RTT as calculated by the kernel in seconds",
			// TODO define a default bucket for stat metrics when we have enough metrics to have something standard
			Buckets:                         []float64{0.0005, 0.001, 0.002, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0},
			NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
			NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
			NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
		}, labelNames(mr.tcpRttAttrs)).MetricVec, clock.Time, cfg.Config.TTL)
		register = append(register, mr.tcpRtt)
	}

	if cfg.CommonCfg.Features.StatsTCPFailedConnections() {
		log.Debug("registering stat tcp failed connections metric")

		mr.tcpFailedConnectionsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPFailedConnections))

		mr.tcpFailedConnections = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPFailedConnections.Prom,
			Help: "counts the TCP failed connections between 2 endpoints",
		}, labelNames(mr.tcpFailedConnectionsAttrs)).MetricVec, clock.Time, cfg.Config.TTL)

		register = append(register, mr.tcpFailedConnections)
	}

	if cfg.Config.Registry != nil {
		cfg.Config.Registry.MustRegister(register...)
	} else {
		mr.promConnect.Register(cfg.Config.Port, cfg.Config.Path, register...)
	}

	mr.input = input.Subscribe(msg.SubscriberName("prom.StatsReporterInput"))
	return mr, nil
}

func (r *statMetricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *statMetricsReporter) collectMetrics(_ context.Context) {
	for stats := range r.input {
		// clock needs to be updated to let the expirer
		// remove the old metrics
		r.clock.Update()
		for _, stat := range stats {
			r.observeTCPRtt(stat)
			r.observeTCPFailedConnections(stat)
		}
	}
}

func (r *statMetricsReporter) observeTCPRtt(stat *ebpf.Stat) {
	if r.tcpRtt == nil || stat.TCPRtt == nil {
		return
	}
	r.tcpRtt.WithLabelValues(labelValues(stat, r.tcpRttAttrs)...).
		Metric.Observe(float64(stat.TCPRtt.SrttUs) / 1_000_000.0)
}

func (r *statMetricsReporter) observeTCPFailedConnections(stat *ebpf.Stat) {
	if r.tcpFailedConnections == nil || stat.TCPFailedConnection == nil {
		return
	}
	r.tcpFailedConnections.WithLabelValues(labelValues(stat, r.tcpFailedConnectionsAttrs)...).
		Metric.Add(1)
}
