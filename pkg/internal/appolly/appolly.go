// Package appobserv provides public access to Beyla application observability as a library. All the other subcomponents
// of Beyla are hidden.
package appolly

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/discover"
	"github.com/grafana/beyla/v2/pkg/internal/pipe"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

func log() *slog.Logger {
	return slog.With("component", "beyla.Instrumenter")
}

// Instrumenter finds and instrument a service/process, and forwards the traces as
// configured by the user
type Instrumenter struct {
	ctx     context.Context
	config  *beyla.Config
	ctxInfo *global.ContextInfo

	// tracesInput is used to communicate the found traces between the ProcessFinder and
	// the ProcessTracer.
	tracesInput chan []request.Span
}

// New Instrumenter, given a Config
func New(ctx context.Context, ctxInfo *global.ContextInfo, config *beyla.Config) *Instrumenter {
	setupFeatureContextInfo(ctx, ctxInfo, config)
	return &Instrumenter{
		ctx:         ctx,
		config:      config,
		ctxInfo:     ctxInfo,
		tracesInput: make(chan []request.Span, config.ChannelBufferLen),
	}
}

// FindAndInstrument searches in background for any new executable matching the
// selection criteria.
// Returns a channel that is closed when the Instrumenter completed all its tasks.
// This is: when the context is cancelled, it has unloaded all the eBPF probes.
func (i *Instrumenter) FindAndInstrument() (<-chan struct{}, error) {
	finder := discover.NewProcessFinder(i.ctx, i.config, i.ctxInfo, i.tracesInput)
	foundProcesses, deletedProcesses, err := finder.Start()
	if err != nil {
		return nil, fmt.Errorf("couldn't start Process Finder: %w", err)
	}

	done := make(chan struct{})
	// In background, listen indefinitely for each new process and run its
	// associated ebpf.ProcessTracer once it is found.
	wg := sync.WaitGroup{}
	go func() {
		log := log()
		for {
			select {
			case <-i.ctx.Done():
				log.Debug("stopped searching for new processes to instrument. Waiting for the eBPF tracers to be unloaded")
				wg.Wait()
				close(done)
				log.Debug("tracers unloaded, exiting FindAndInstrument")
				return
			case pt := <-foundProcesses:
				log.Debug("running tracer for new process",
					"inode", pt.FileInfo.Ino, "pid", pt.FileInfo.Pid, "exec", pt.FileInfo.CmdExePath)
				if pt.Tracer != nil {
					wg.Add(1)
					go func() {
						defer wg.Done()
						pt.Tracer.Run(i.ctx, i.tracesInput)
					}()
				}
			case dp := <-deletedProcesses:
				log.Debug("stopping ProcessTracer because there are no more instances of such process",
					"inode", dp.FileInfo.Ino, "pid", dp.FileInfo.Pid, "exec", dp.FileInfo.CmdExePath)
				if dp.Tracer != nil {
					dp.Tracer.UnlinkExecutable(dp.FileInfo)
				}
			}
		}
	}()
	// TODO: wait until all the resources have been freed/unmounted
	return done, nil
}

// ReadAndForward keeps listening for traces in the BPF map, then reads,
// processes and forwards them
func (i *Instrumenter) ReadAndForward() error {
	log := log()
	log.Debug("creating instrumentation pipeline")

	bp, err := pipe.Build(i.ctx, i.config, i.ctxInfo, i.tracesInput)
	if err != nil {
		return fmt.Errorf("can't instantiate instrumentation pipeline: %w", err)
	}

	log.Info("Starting main node")

	bp.Run(i.ctx)

	log.Info("exiting auto-instrumenter")

	return nil
}

func setupFeatureContextInfo(ctx context.Context, ctxInfo *global.ContextInfo, config *beyla.Config) {
	ctxInfo.AppO11y.ReportRoutes = config.Routes != nil
	setupKubernetes(ctx, ctxInfo)
}

// setupKubernetes sets up common Kubernetes database and API clients that need to be accessed
// from different stages in the Beyla pipeline
func setupKubernetes(ctx context.Context, ctxInfo *global.ContextInfo) {
	if !ctxInfo.K8sInformer.IsKubeEnabled() {
		return
	}

	if err := refreshK8sInformerCache(ctx, ctxInfo); err != nil {
		slog.Error("can't init Kubernetes informer. You can't setup Kubernetes discovery and your"+
			" traces won't be decorated with Kubernetes metadata", "error", err)
		ctxInfo.K8sInformer.ForceDisable()
		return
	}
}

func refreshK8sInformerCache(ctx context.Context, ctxInfo *global.ContextInfo) error {
	// force the cache to be populated and cached
	_, err := ctxInfo.K8sInformer.Get(ctx)
	return err
}
