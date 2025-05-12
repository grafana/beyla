// Package appobserv provides public access to Beyla application observability as a library. All the other subcomponents
// of Beyla are hidden.
package appolly

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/discover"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/pipe"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/traces"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
	"github.com/grafana/beyla/v2/pkg/transform"
)

var errShutdownTimeout = errors.New("graceful shutdown has timed out")

func log() *slog.Logger {
	return slog.With("component", "beyla.Instrumenter")
}

// Instrumenter finds and instrument a service/process, and forwards the traces as
// configured by the user
type Instrumenter struct {
	config    *beyla.Config
	ctxInfo   *global.ContextInfo
	tracersWg *sync.WaitGroup
	bp        *pipe.Instrumenter

	// tracesInput is used to communicate the found traces between the ProcessFinder and
	// the ProcessTracer.
	tracesInput       *msg.Queue[[]request.Span]
	processEventInput *msg.Queue[exec.ProcessEvent]
	peGraphBuilder    *swarm.Instancer
}

// New Instrumenter, given a Config
func New(ctx context.Context, ctxInfo *global.ContextInfo, config *beyla.Config) (*Instrumenter, error) {
	setupFeatureContextInfo(ctx, ctxInfo, config)

	tracesInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(config.ChannelBufferLen))

	newEventQueue := func() *msg.Queue[exec.ProcessEvent] {
		return msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(config.ChannelBufferLen), msg.NotBlockIfNoSubscribers())
	}

	swi := &swarm.Instancer{}

	processEventsInput := newEventQueue()
	processEventsHostDecorated := newEventQueue()

	swi.Add(traces.HostProcessEventDecoratorProvider(
		&config.Attributes.InstanceID,
		processEventsInput,
		processEventsHostDecorated,
	))

	processEventsKubeDecorated := newEventQueue()
	swi.Add(transform.KubeProcessEventDecoratorProvider(
		ctxInfo,
		&config.Attributes.Kubernetes,
		processEventsHostDecorated,
		processEventsKubeDecorated,
	))

	bp, err := pipe.Build(ctx, config, ctxInfo, tracesInput, processEventsKubeDecorated)
	if err != nil {
		return nil, fmt.Errorf("can't instantiate instrumentation pipeline: %w", err)
	}

	return &Instrumenter{
		config:            config,
		ctxInfo:           ctxInfo,
		tracersWg:         &sync.WaitGroup{},
		tracesInput:       tracesInput,
		processEventInput: processEventsInput,
		bp:                bp,
		peGraphBuilder:    swi,
	}, nil
}

// FindAndInstrument searches in background for any new executable matching the
// selection criteria.
// Returns a channel that is closed when the Instrumenter completed all its tasks.
// This is: when the context is cancelled, it has unloaded all the eBPF probes.
func (i *Instrumenter) FindAndInstrument(ctx context.Context) error {
	finder := discover.NewProcessFinder(i.config, i.ctxInfo, i.tracesInput)
	processEvents, err := finder.Start(ctx)
	if err != nil {
		return fmt.Errorf("couldn't start Process Finder: %w", err)
	}

	// In the background process any process found events and annotate them with
	// the Host or Kubernetes metadata
	graph, err := i.peGraphBuilder.Instance(ctx)
	if err == nil {
		go i.processEventsPipeline(ctx, graph)
	} else {
		return fmt.Errorf("couldn't start Process Event pipeline: %w", err)
	}

	// In background, listen indefinitely for each new process and run its
	// associated ebpf.ProcessTracer once it is found.
	go i.instrumentedEventLoop(ctx, processEvents)

	// TODO: wait until all the resources have been freed/unmounted
	return nil
}

func (i *Instrumenter) instrumentedEventLoop(ctx context.Context, processEvents <-chan discover.Event[*ebpf.Instrumentable]) {
	log := log()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-processEvents:
			switch ev.Type {
			case discover.EventCreated:
				pt := ev.Obj
				log.Debug("running tracer for new process",
					"inode", pt.FileInfo.Ino, "pid", pt.FileInfo.Pid, "exec", pt.FileInfo.CmdExePath)
				if pt.Tracer != nil {
					i.tracersWg.Add(1)
					go func() {
						defer i.tracersWg.Done()
						pt.Tracer.Run(ctx, i.tracesInput)
					}()
				}
				i.handleAndDispatchProcessEvent(exec.ProcessEvent{Type: exec.ProcessEventCreated, File: pt.FileInfo})
			case discover.EventDeleted:
				dp := ev.Obj
				log.Debug("stopping ProcessTracer because there are no more instances of such process",
					"inode", dp.FileInfo.Ino, "pid", dp.FileInfo.Pid, "exec", dp.FileInfo.CmdExePath)
				if dp.Tracer != nil {
					dp.Tracer.UnlinkExecutable(dp.FileInfo)
				}
				i.handleAndDispatchProcessEvent(exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: dp.FileInfo})
			case discover.EventInstanceDeleted:
				i.handleAndDispatchProcessEvent(exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: ev.Obj.FileInfo})
			default:
				log.Error("BUG ALERT! unknown event type", "type", ev.Type)
			}
		}
	}
}

// ReadAndForward keeps listening for traces in the BPF map, then reads,
// processes and forwards them
func (i *Instrumenter) ReadAndForward(ctx context.Context) error {
	log := log()
	log.Debug("creating instrumentation pipeline")

	log.Info("Starting main node")

	i.bp.Run(ctx)

	<-ctx.Done()

	log.Info("exiting auto-instrumenter")

	err := i.stop()
	if err != nil {
		return fmt.Errorf("failed to stop auto-instrumenter: %w", err)
	}

	return nil
}

func (i *Instrumenter) stop() error {
	log := log()

	stopped := make(chan struct{})
	go func() {
		log.Debug("stopped searching for new processes to instrument. Waiting for the eBPF tracers to be unloaded")
		i.tracersWg.Wait()
		stopped <- struct{}{}
		log.Debug("tracers unloaded, exiting FindAndInstrument")
	}()

	select {
	case <-time.After(i.config.ShutdownTimeout):
		return errShutdownTimeout
	case <-stopped:
		return nil
	}
}

func (i *Instrumenter) handleAndDispatchProcessEvent(pe exec.ProcessEvent) {
	i.processEventInput.Send(pe)
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

func (i *Instrumenter) processEventsPipeline(ctx context.Context, graph *swarm.Runner) {
	graph.Start(ctx)
	// run until either the graph is finished or the context is cancelled
	select {
	case <-graph.Done():
	case <-ctx.Done():
	}
}
