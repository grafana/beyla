package prom

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	"github.com/grafana/beyla/v2/pkg/export/expire"
	"github.com/grafana/beyla/v2/pkg/internal/connector"
	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
)

// injectable function reference for testing

// NetPrometheusConfig for network metrics just wraps the global prom.NetPrometheusConfig as provided by the user
type NetPrometheusConfig struct {
	Config             *PrometheusConfig
	AttributeSelectors attributes.Selection
	// Deprecated: to be removed in Beyla 3.0 with BEYLA_NETWORK_METRICS bool flag
	GloballyEnabled bool
}

// nolint:gocritic
func (p NetPrometheusConfig) Enabled() bool {
	return p.Config != nil && p.Config.EndpointEnabled() && (p.Config.NetworkMetricsEnabled() || p.GloballyEnabled)
}

type netMetricsReporter struct {
	cfg *PrometheusConfig

	flowBytes *Expirer[prometheus.Counter]
	interZone *Expirer[prometheus.Counter]

	promConnect *connector.PrometheusManager

	flowAttrs      []attributes.Field[*ebpf.Record, string]
	interZoneAttrs []attributes.Field[*ebpf.Record, string]

	clock *expire.CachedClock

	input <-chan []*ebpf.Record
}

func NetPrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *NetPrometheusConfig,
	input *msg.Queue[[]*ebpf.Record],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the swarm library just ignore it.
			return swarm.EmptyRunFunc()
		}
		reporter, err := newNetReporter(ctxInfo, cfg, input)
		if err != nil {
			return nil, err
		}
		if cfg.Config.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

func newNetReporter(
	ctxInfo *global.ContextInfo,
	cfg *NetPrometheusConfig,
	input *msg.Queue[[]*ebpf.Record],
) (*netMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.AttributeSelectors)
	if err != nil {
		return nil, fmt.Errorf("network Prometheus exporter attributes enable: %w", err)
	}

	clock := expire.NewCachedClock(timeNow)
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &netMetricsReporter{
		cfg:         cfg.Config,
		promConnect: ctxInfo.Prometheus,
		clock:       clock,
	}

	var register []prometheus.Collector
	log := slog.With("component", "prom.NetworkEndpoint")
	if cfg.GloballyEnabled || mr.cfg.NetworkFlowBytesEnabled() {
		log.Debug("registering network flow bytes metric")
		mr.flowAttrs = attributes.PrometheusGetters(
			ebpf.RecordStringGetters,
			provider.For(attributes.BeylaNetworkFlow))

		mr.flowBytes = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.BeylaNetworkFlow.Prom,
			Help: "bytes submitted from a source network endpoint to a destination network endpoint",
		}, labelNames(mr.flowAttrs)).MetricVec, clock.Time, cfg.Config.TTL)
		register = append(register, mr.flowBytes)
	}

	if mr.cfg.NetworkInterzoneMetricsEnabled() {
		log.Debug("registering network inter-zone metric")
		mr.interZoneAttrs = attributes.PrometheusGetters(
			ebpf.RecordStringGetters,
			provider.For(attributes.BeylaNetworkInterZone))

		mr.interZone = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.BeylaNetworkInterZone.Prom,
			Help: "bytes submitted between different cloud availability zones",
		}, labelNames(mr.interZoneAttrs)).MetricVec, clock.Time, cfg.Config.TTL)
		register = append(register, mr.interZone)
	}

	if cfg.Config.Registry != nil {
		cfg.Config.Registry.MustRegister(register...)
	} else {
		mr.promConnect.Register(cfg.Config.Port, cfg.Config.Path, register...)
	}

	mr.input = input.Subscribe()
	return mr, nil
}

func (r *netMetricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *netMetricsReporter) collectMetrics(_ context.Context) {
	for flows := range r.input {
		// clock needs to be updated to let the expirer
		// remove the old metrics
		r.clock.Update()
		for _, flow := range flows {
			r.observeFlowBytes(flow)
			r.observeInterZone(flow)
		}
	}
}

func (r *netMetricsReporter) observeFlowBytes(flow *ebpf.Record) {
	if r.flowBytes == nil {
		return
	}
	r.flowBytes.WithLabelValues(labelValues(flow, r.flowAttrs)...).
		metric.Add(float64(flow.Metrics.Bytes))
}

func (r *netMetricsReporter) observeInterZone(flow *ebpf.Record) {
	if r.interZone == nil || flow.Attrs.SrcZone == flow.Attrs.DstZone {
		return
	}
	r.interZone.WithLabelValues(labelValues(flow, r.interZoneAttrs)...).
		metric.Add(float64(flow.Metrics.Bytes))
}
