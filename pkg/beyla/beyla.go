package beyla

import (
	"context"
	"fmt"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/connector"
	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf"
	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"
)

func log() *slog.Logger {
	return slog.With("component", "beyla.Instrumenter")
}

type Instrumenter struct {
	config  *pipe.Config
	ctxInfo *global.ContextInfo
	// TODO: before splitting the executable, tracer interface passed here should have
	// restricted functionality: just read and forward data from already mounted BPF maps
	tracer *ebpf.ProcessTracer
}

func New(config *pipe.Config) *Instrumenter {
	return &Instrumenter{
		config:  config,
		ctxInfo: buildContextInfo(config),
	}
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
	if i.ctxInfo.ServiceName == "" {
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

func example() {

}
