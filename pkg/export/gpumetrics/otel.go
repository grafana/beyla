package gpumetrics

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// sharedExporter lets this node stop its reader without shutting down other nodes' exporter.
type sharedExporter struct{ sdkmetric.Exporter }

func (sharedExporter) Shutdown(context.Context) error { return nil }

// OTELConfig connects the GPU metrics to the shared OTLP exporter.
type OTELConfig struct {
	Enabled  bool
	HostID   string
	HostName string
	Interval time.Duration
	Exporter func(context.Context) (sdkmetric.Exporter, error)
}

// OTELExport reports the GPU metrics over OTLP from a terminal pipeline node.
func OTELExport(cfg OTELConfig, source Source, events *msg.Queue[exec.ProcessEvent]) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled {
			return swarm.EmptyRunFunc()
		}
		exporter, err := cfg.Exporter(ctx)
		if err != nil {
			return nil, fmt.Errorf("creating GPU metrics exporter: %w", err)
		}
		procs := newProcesses()
		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(resource.NewSchemaless(
				attribute.String(string(hostID), cfg.HostID),
				attribute.String(string(hostName), cfg.HostName),
			)),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(sharedExporter{exporter}, sdkmetric.WithInterval(cfg.Interval))))
		if err := registerInstruments(provider, source, procs); err != nil {
			_ = provider.Shutdown(ctx)
			return nil, err
		}
		watch := procs.watch(events, "gpumetrics.OTEL")
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

func registerInstruments(provider otelmetric.MeterProvider, source Source, procs *processes) error {
	meter := provider.Meter("github.com/grafana/beyla/gpu")
	instruments := make(map[*metricDef]otelmetric.Float64Observable, len(allMetrics))
	observables := make([]otelmetric.Observable, 0, len(allMetrics))
	for _, def := range allMetrics {
		var inst otelmetric.Float64Observable
		var err error
		switch def.kind {
		case kindGauge:
			inst, err = meter.Float64ObservableGauge(def.otel,
				otelmetric.WithDescription(def.help), otelmetric.WithUnit(def.unit))
		case kindUpDownCounter:
			inst, err = meter.Float64ObservableUpDownCounter(def.otel,
				otelmetric.WithDescription(def.help), otelmetric.WithUnit(def.unit))
		case kindCounter:
			inst, err = meter.Float64ObservableCounter(def.otel,
				otelmetric.WithDescription(def.help), otelmetric.WithUnit(def.unit))
		}
		if err != nil {
			return fmt.Errorf("creating %s instrument: %w", def.otel, err)
		}
		instruments[def] = inst
		observables = append(observables, inst)
	}
	_, err := meter.RegisterCallback(func(_ context.Context, o otelmetric.Observer) error {
		observe(source.Collect(), procs, func(def *metricDef, value float64, labelValues ...string) {
			attrs := make([]attribute.KeyValue, len(def.labels))
			for i, name := range def.labels {
				attrs[i] = attribute.String(string(name), labelValues[i])
			}
			o.ObserveFloat64(instruments[def], value, otelmetric.WithAttributes(attrs...))
		})
		return nil
	}, observables...)
	if err != nil {
		return fmt.Errorf("registering GPU metrics callback: %w", err)
	}
	return nil
}
