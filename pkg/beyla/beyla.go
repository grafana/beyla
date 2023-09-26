// Package beyla provides public access to Beyla as a library. All the other subcomponents
// of Beyla are hidden.
package beyla

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
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

	// tracesInput is used to communicate the found traces between the ProcessFinder and
	// the ProcessTracer.
	// TODO: When we split beyla into two executables, probably the BPF map
	// should be the traces' communication mechanism instead of a native channel
	tracesInput chan []request.Span

	// TODO: temporary hack. REMOVE
	// This will force that the pipeline is not created until we have a service name.
	// In the following PR this will be removed, as we will include the service name
	// in the Span information, and create dynamically OTEL resources for each new
	// service (as we already do for system wide configuration): remove ASAP
	TempHackWaitForServiceName chan struct{}
}

// New Instrumenter, given a Config
func New(config *Config) *Instrumenter {
	return &Instrumenter{
		config:                     (*pipe.Config)(config),
		ctxInfo:                    buildContextInfo((*pipe.Config)(config)),
		tracesInput:                make(chan []request.Span, config.ChannelBufferLen),
		TempHackWaitForServiceName: make(chan struct{}),
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

// FindAndInstrument searches in background for any new executable matching the
// selection criteria.
func (i *Instrumenter) FindAndInstrument(ctx context.Context) error {
	finder := &ebpf.ProcessFinder{
		Cfg:     i.config,
		CtxInfo: i.ctxInfo,
		Metrics: i.ctxInfo.Metrics,
	}
	foundProcesses, err := finder.Start(ctx)
	if err != nil {
		return fmt.Errorf("couldn't start Process Finder: %w", err)
	}
	// In background, listen indefinitely for each new process and run its
	// associated ebpf.ProcessTracer once it is found.
	go func() {
		for {
			select {
			case <-ctx.Done():
				lg := log()
				lg.Debug("stopped searching for new processes to instrument")
				if err := finder.Close(); err != nil {
					lg.Warn("error closing process finder instance", "error", err)
				}
				return
			case pt := <-foundProcesses:
				select {
				case <-i.TempHackWaitForServiceName:
					// already closed. Not closing again!
				default:
					close(i.TempHackWaitForServiceName)
				}
				go pt.Run(ctx, i.tracesInput)
			}
		}
	}()
	return nil
}

// ReadAndForward keeps listening for traces in the BPF map, then reads,
// processes and forwards them
func (i *Instrumenter) ReadAndForward(ctx context.Context) error {
	log := log()
	log.Debug("creating instrumentation pipeline")
	<-i.TempHackWaitForServiceName

	// TODO: when we split the executable, tracer should be reconstructed somehow
	// from this instance
	bp, err := pipe.Build(ctx, i.config, i.ctxInfo, i.tracesInput)
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
		ChannelBufferLen: config.ChannelBufferLen,
		K8sDecoration:    config.Kubernetes.Enabled(),
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
