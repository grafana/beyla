// Package beyla provides public access to Beyla as a library. All the other subcomponents
// of Beyla are hidden.
package beyla

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/internal/connector"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/pipe"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/pipe/global"
)

// Config as provided by the user to configure and run Beyla
type Config pipe.Config

func log() *slog.Logger {
	return slog.With("component", "beyla.Instrumenter")
}

// Instrumenter finds and instrument a service/process, and forwards the traces as
// configured by the user
type Instrumenter struct {
	config  *pipe.Config
	ctxInfo *global.ContextInfo
	// TODO: before splitting the executable, tracer interface passed here should have
	// restricted functionality: just read and forward data from already mounted BPF maps
	tracer *ebpf.ProcessTracer
}

// New Instrumenter, given a Config
func New(config *Config) *Instrumenter {
	return &Instrumenter{
		config:  (*pipe.Config)(config),
		ctxInfo: buildContextInfo((*pipe.Config)(config)),
	}
}

// LoadConfig loads and validates configuration.
// Configuration from multiple source is overridden in the following order
// (from less to most priority):
// 1 - Default configuration
// 2 - Contents of the provided file reader (nillable)
// 3 - Environment variables
func LoadConfig(reader io.Reader) (*Config, error) {
	cfg, err := pipe.LoadConfig(reader)
	if err != nil {
		return nil, err
	}
	return (*Config)(cfg), nil
}

// FindTarget finds the target executable or service and instruments it. In addition
// it mounts the required BPF maps to be used by ReadAndForward
func (i *Instrumenter) FindTarget(ctx context.Context) error {
	log().Info("creating instrumentation pipeline")
	var err error
	i.tracer, err = ebpf.FindAndInstrument(ctx, &i.config.EBPF, i.ctxInfo.Metrics)
	if err != nil {
		return fmt.Errorf("can't find an instrument executable: %w", err)
	}
	// If system-wide tracing is set, we don't use the initially-found
	// executable name as service name, as it might be anything.
	// We'll use the service name as traced from eBPF
	if i.ctxInfo.ServiceName == "" && !i.config.EBPF.SystemWide {
		i.ctxInfo.ServiceName = i.tracer.ELFInfo.ExecutableName()
	}
	return nil
}

// ReadAndForward keeps listening for traces in the BPF map, then reads,
// processes and forwards them
func (i *Instrumenter) ReadAndForward(ctx context.Context) error {
	log := log()
	// TODO: when we split the executable, tracer should be reconstructed somehow
	// from this instance
	bp, err := pipe.Build(ctx, i.config, i.ctxInfo, i.tracer)
	if err != nil {
		return fmt.Errorf("can't instantiate instrumentation pipeline: %w", err)
	}

	log.Info("Starting main node")

	bp.Run(ctx)

	log.Info("exiting auto-instrumenter")

	return nil
}

// buildContextInfo populates some globally shared components and properties
// from the user-provided configuration
func buildContextInfo(config *pipe.Config) *global.ContextInfo {
	promMgr := &connector.PrometheusManager{}
	ctxInfo := &global.ContextInfo{
		ReportRoutes:     config.Routes != nil,
		Prometheus:       promMgr,
		ServiceName:      config.ServiceName,
		ServiceNamespace: config.ServiceNamespace,
	}
	if config.InternalMetrics.Prometheus.Port != 0 {
		slog.Debug("reporting internal metrics as Prometheus")
		ctxInfo.Metrics = imetrics.NewPrometheusReporter(&config.InternalMetrics.Prometheus, promMgr)
		// Prometheus manager also has its own internal metrics, so we need to pass the imetrics reporter
		// TODO: remove this dependency cycle and let prommgr to create and return the PrometheusReporter
		promMgr.InstrumentWith(ctxInfo.Metrics)
	} else {
		slog.Debug("not reporting internal metrics")
		ctxInfo.Metrics = imetrics.NoopReporter{}
	}
	return ctxInfo
}
