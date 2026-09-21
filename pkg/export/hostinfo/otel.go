package hostinfo

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v3/pkg/export/extraattributes/names"
)

const otelName = "traces.host.info"

// sharedExporter lets this node stop its reader without shutting down other nodes' exporter.
type sharedExporter struct{ sdkmetric.Exporter }

func (sharedExporter) Shutdown(context.Context) error { return nil }

// OTELConfig connects host-info metrics to the shared OTLP exporter.
type OTELConfig struct {
	HostID   string
	Enabled  bool
	Interval time.Duration
	TTL      time.Duration
	Exporter func(context.Context) (sdkmetric.Exporter, error)
}

// OTELExport reports host activity as an OTLP gauge from a terminal pipeline node.
func OTELExport(cfg OTELConfig, input *msg.Queue[[]request.Span], events *msg.Queue[exec.ProcessEvent]) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled {
			return swarm.EmptyRunFunc()
		}
		activity := newState()
		exporter, err := cfg.Exporter(ctx)
		if err != nil {
			return nil, fmt.Errorf("creating host-info exporter: %w", err)
		}
		provider := sdkmetric.NewMeterProvider(sdkmetric.WithResource(resource.Empty()),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(sharedExporter{exporter}, sdkmetric.WithInterval(cfg.Interval))))
		_, err = provider.Meter("github.com/grafana/beyla").Int64ObservableGauge(otelName,
			otelmetric.WithInt64Callback(func(_ context.Context, observer otelmetric.Int64Observer) error {
				if activity.hasActiveProcesses(time.Now(), cfg.TTL) {
					observer.Observe(1, otelmetric.WithAttributes(attribute.String(string(names.GrafanaHostID), cfg.HostID)))
				}
				return nil
			}))
		if err != nil {
			_ = provider.Shutdown(ctx)
			return nil, err
		}
		watch := activity.watchActivity(input, events, "hostinfo.OTEL")
		return func(ctx context.Context) {
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = provider.Shutdown(shutdownCtx)
			}()
			watch(ctx)
		}, nil
	}
}
