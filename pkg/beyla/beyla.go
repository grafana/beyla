// Package beyla provides public access to Beyla as a library. All the other subcomponents
// of Beyla are hidden.
package beyla

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"k8s.io/client-go/kubernetes"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/discover"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	kube2 "github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/transform"
	"github.com/grafana/beyla/pkg/internal/transform/kube"
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
}

// New Instrumenter, given a Config
func New(config *Config) *Instrumenter {
	return &Instrumenter{
		config:      (*pipe.Config)(config),
		ctxInfo:     buildContextInfo((*pipe.Config)(config)),
		tracesInput: make(chan []request.Span, config.ChannelBufferLen),
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
	finder := discover.NewProcessFinder(ctx, i.config, i.ctxInfo)
	foundProcesses, deletedProcesses, err := finder.Start(i.config)
	if err != nil {
		return fmt.Errorf("couldn't start Process Finder: %w", err)
	}
	// In background, listen indefinitely for each new process and run its
	// associated ebpf.ProcessTracer once it is found.
	go func() {
		log := log()
		type cancelCtx struct {
			ctx    context.Context
			cancel func()
		}
		contexts := map[uint64]cancelCtx{}
		for {
			select {
			case <-ctx.Done():
				log.Debug("stopped searching for new processes to instrument")
				return
			case pt := <-foundProcesses:
				log.Debug("running tracer for new process",
					"inode", pt.ELFInfo.Ino, "pid", pt.ELFInfo.Pid, "exec", pt.ELFInfo.CmdExePath)
				cctx, ok := contexts[pt.ELFInfo.Ino]
				if !ok {
					cctx.ctx, cctx.cancel = context.WithCancel(ctx)
					contexts[pt.ELFInfo.Ino] = cctx
				}
				go pt.Run(cctx.ctx, i.tracesInput)
			case dp := <-deletedProcesses:
				log.Debug("stopping ProcessTracer because there are no more instances of such process",
					"inode", dp.FileInfo.Ino, "pid", dp.FileInfo.Pid, "exec", dp.FileInfo.CmdExePath)
				if cctx, ok := contexts[dp.FileInfo.Ino]; ok {
					delete(contexts, dp.FileInfo.Ino)
					cctx.cancel()
				}
			}
		}
	}()
	// TODO: wait until all the resources have been freed/unmounted
	return nil
}

// ReadAndForward keeps listening for traces in the BPF map, then reads,
// processes and forwards them
func (i *Instrumenter) ReadAndForward(ctx context.Context) error {
	log := log()
	log.Debug("creating instrumentation pipeline")

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
	k8sCfg := &config.Attributes.Kubernetes
	ctxInfo := &global.ContextInfo{
		ReportRoutes: config.Routes != nil,
		Prometheus:   promMgr,
		K8sEnabled:   k8sCfg.Enabled(),
	}
	if ctxInfo.K8sEnabled {
		setupKubernetes(k8sCfg, ctxInfo)
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

// setupKubernetes sets up common Kubernetes database and API clients that need to be accessed
// from different stages in the Beyla pipeline
func setupKubernetes(k8sCfg *transform.KubernetesDecorator, ctxInfo *global.ContextInfo) {

	config, err := kube2.LoadConfig(k8sCfg.KubeconfigPath)
	if err != nil {
		slog.Error("can't read kubernetes config. You can't setup Kubernetes discovery and your"+
			" traces won't be decorated with Kubernetes metadata", "error", err)
		ctxInfo.K8sEnabled = false
		return
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		slog.Error("can't init Kubernetes client. You can't setup Kubernetes discovery and your"+
			" traces won't be decorated with Kubernetes metadata", "error", err)
		ctxInfo.K8sEnabled = false
		return
	}

	ctxInfo.K8sInformer = &kube2.Metadata{}
	if err := ctxInfo.K8sInformer.InitFromClient(kubeClient, k8sCfg.InformersSyncTimeout); err != nil {
		slog.Error("can't init Kubernetes informer. You can't setup Kubernetes discovery and your"+
			" traces won't be decorated with Kubernetes metadata", "error", err)
		ctxInfo.K8sInformer = nil
		ctxInfo.K8sEnabled = false
		return
	}

	if ctxInfo.K8sDatabase, err = kube.StartDatabase(ctxInfo.K8sInformer); err != nil {
		slog.Error("can't setup Kubernetes database. Your traces won't be decorated with Kubernetes metadata",
			"error", err)
		ctxInfo.K8sEnabled = false
	}
}
