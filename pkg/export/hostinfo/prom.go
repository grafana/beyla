package hostinfo

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v3/pkg/export/extraattributes/names"
)

const promName = "traces_host_info"

type collector struct {
	state *state
	desc  *prometheus.Desc
	host  string
	ttl   time.Duration
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	if c.state.hasActiveProcesses(time.Now(), c.ttl) {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 1, c.host)
	}
}

// PromConfig connects host-info metrics to the existing Prometheus endpoint.
type PromConfig struct {
	HostID    string
	Enabled   bool
	TTL       time.Duration
	Register  func(prometheus.Collector) error
	StartHTTP func(context.Context)
}

// PromExport reports host activity as a Prometheus gauge from a terminal pipeline node.
func PromExport(cfg PromConfig, input *msg.Queue[[]request.Span], events *msg.Queue[exec.ProcessEvent]) swarm.InstanceFunc {
	return func(context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled {
			return swarm.EmptyRunFunc()
		}
		activity := newState()
		c := &collector{state: activity, host: cfg.HostID, ttl: cfg.TTL,
			desc: prometheus.NewDesc(promName, "Host running instrumented applications", []string{names.GrafanaHostID.Prom()}, nil)}
		if err := cfg.Register(c); err != nil {
			return nil, err
		}
		watch := activity.watchActivity(input, events, "hostinfo.Prom")
		return func(ctx context.Context) {
			if cfg.StartHTTP != nil {
				go cfg.StartHTTP(ctx)
			}
			watch(ctx)
		}, nil
	}
}
