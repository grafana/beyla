// Package appobserv provides public access to Beyla application observability as a library. All the other subcomponents
// of Beyla are hidden.
package appolly

import (
	"context"
	"fmt"
	"log/slog"

	"k8s.io/client-go/kubernetes"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/discover"
	kube2 "github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/transform/kube"
	"github.com/grafana/beyla/pkg/transform"
)

func log() *slog.Logger {
	return slog.With("component", "beyla.Instrumenter")
}

// Instrumenter finds and instrument a service/process, and forwards the traces as
// configured by the user
type Instrumenter struct {
	config  *beyla.Config
	ctxInfo *global.ContextInfo

	// tracesInput is used to communicate the found traces between the ProcessFinder and
	// the ProcessTracer.
	// TODO: When we split beyla into two executables, probably the BPF map
	// should be the traces' communication mechanism instead of a native channel
	tracesInput chan []request.Span
}

// New Instrumenter, given a Config
func New(ctxInfo *global.ContextInfo, config *beyla.Config) *Instrumenter {
	setupFeatureContextInfo(ctxInfo, config)
	return &Instrumenter{
		config:      config,
		ctxInfo:     ctxInfo,
		tracesInput: make(chan []request.Span, config.ChannelBufferLen),
	}
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

func setupFeatureContextInfo(ctxInfo *global.ContextInfo, config *beyla.Config) {
	ctxInfo.AppO11y.ReportRoutes = config.Routes != nil
	setupKubernetes(ctxInfo, &config.Attributes.Kubernetes)
}

// setupKubernetes sets up common Kubernetes database and API clients that need to be accessed
// from different stages in the Beyla pipeline
func setupKubernetes(ctxInfo *global.ContextInfo, k8sCfg *transform.KubernetesDecorator) {
	if !ctxInfo.K8sEnabled {
		return
	}
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

	ctxInfo.AppO11y.K8sInformer = &kube2.Metadata{}
	if err := ctxInfo.AppO11y.K8sInformer.InitFromClient(kubeClient, k8sCfg.InformersSyncTimeout); err != nil {
		slog.Error("can't init Kubernetes informer. You can't setup Kubernetes discovery and your"+
			" traces won't be decorated with Kubernetes metadata", "error", err)
		ctxInfo.AppO11y.K8sInformer = nil
		ctxInfo.K8sEnabled = false
		return
	}

	if ctxInfo.AppO11y.K8sDatabase, err = kube.StartDatabase(ctxInfo.AppO11y.K8sInformer); err != nil {
		slog.Error("can't setup Kubernetes database. Your traces won't be decorated with Kubernetes metadata",
			"error", err)
		ctxInfo.K8sEnabled = false
	}
}
