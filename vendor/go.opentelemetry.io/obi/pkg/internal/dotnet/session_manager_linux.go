// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

// SessionManager owns one asynchronous EventPipe reader per discovered process.
type SessionManager struct {
	ctx      context.Context
	interval time.Duration
	timeout  time.Duration
	queue    *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot]
	mu       sync.Mutex
	targets  map[app.PID]*collection
	closed   bool
	workers  sync.WaitGroup
}

type collection struct {
	startTime uint64
	cancel    context.CancelFunc
	done      chan struct{}
}

func NewSessionManager(ctx context.Context, interval, timeout time.Duration, queue *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot]) *SessionManager {
	return &SessionManager{ctx: ctx, interval: interval, timeout: timeout, queue: queue, targets: make(map[app.PID]*collection)}
}

// Start captures the discovered process before scheduling attachment. Repeated
// notifications for the same incarnation share one session.
func (c *SessionManager) Start(file *exec.FileInfo) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		return nil
	}
	if c.interval <= 0 || c.timeout <= 0 || c.queue == nil {
		return errors.New(".NET session manager requires a positive sampling interval, timeout, and a metrics queue")
	}
	pid, startTime := file.Pid(), file.StartTime()
	previous := c.targets[pid]
	if previous != nil && previous.startTime == startTime {
		return nil
	}
	process, err := procs.OpenProcessHandle(pid, startTime)
	if err != nil {
		return err
	}
	if previous != nil {
		previous.cancel()
	}
	if file.RuntimeMetricGeneration(pid) == 0 {
		file.SetRuntimeMetricGeneration(pid, ebpfcommon.NewRuntimeMetricGeneration())
	}
	ctx, cancel := context.WithCancel(c.ctx)
	target := &collection{startTime: startTime, cancel: cancel, done: make(chan struct{})}
	c.targets[pid] = target
	c.workers.Go(func() {
		defer close(target.done)
		defer func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.targets[pid] == target {
				delete(c.targets, pid)
			}
		}()
		defer process.Close()
		defer cancel()
		if previous != nil {
			select {
			case <-previous.done:
			case <-ctx.Done():
				return
			}
		}
		c.run(ctx, process, file)
	})
	return nil
}

// Remove cancels only the process incarnation named by the discovery event.
func (c *SessionManager) Remove(file *exec.FileInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if target := c.targets[file.Pid()]; target != nil && target.startTime == file.StartTime() {
		target.cancel()
	}
}

// Close cancels attachment and readers, then waits for bounded session cleanup.
func (c *SessionManager) Close() {
	c.mu.Lock()
	c.closed = true
	for _, target := range c.targets {
		target.cancel()
	}
	c.mu.Unlock()
	c.workers.Wait()
}

// run retries transient attachment failures while the pinned process is alive.
// Reconnected sessions keep the last published totals as their new baseline.
func (c *SessionManager) run(ctx context.Context, process *procs.ProcessHandle, file *exec.FileInfo) {
	log := slog.With("component", "dotnet.SessionManager", "pid", process.PID())
	var totals [runtimemetrics.DotnetGCGenerationCount]uint64
	warned := false
	generation := file.RuntimeMetricGeneration(process.PID())
	defer func() {
		c.queue.SendCtx(c.ctx, []runtimemetrics.RuntimeMetricSnapshot{{
			Service: file.ServiceAttrs(), PID: process.PID(), Generation: generation,
			Time: time.Now(), Removed: true, Dotnet: &runtimemetrics.DotnetRuntimeMetricSnapshot{},
		}})
	}()
	for ctx.Err() == nil {
		if err := process.Alive(); err != nil {
			if !errors.Is(err, unix.ESRCH) {
				log.Warn("unable to check .NET process liveness", "error", err)
			}
			return
		}
		setupCtx, cancel := context.WithTimeout(ctx, c.timeout)
		target, err := resolveDiagnosticTarget(setupCtx, process, file.ServiceAttrs().EnvVars["TMPDIR"])
		var session *eventPipeSession
		if err == nil {
			session, err = startEventPipe(setupCtx, target.socketPath, c.interval)
		}
		cancel()
		if err == nil {
			log.Debug("started EventPipe GC collection", "session", session.id)
			base := totals
			err = c.readSession(ctx, session, target.info.PID, func(snapshot *runtimemetrics.DotnetRuntimeMetricSnapshot) error {
				for gcGeneration, count := range snapshot.GCCollections {
					if *count > math.MaxInt64-base[gcGeneration] {
						return errors.New(".NET GC collections exceed exporter integer range")
					}
					*count += base[gcGeneration]
				}
				for gcGeneration, count := range snapshot.GCCollections {
					totals[gcGeneration] = *count
				}
				c.queue.SendCtx(ctx, []runtimemetrics.RuntimeMetricSnapshot{{
					Service: file.ServiceAttrs(), PID: process.PID(), Generation: generation,
					Time: time.Now(), Dotnet: snapshot,
				}})
				return nil
			})
		}
		if target.directory != nil {
			_ = target.directory.Close()
		}
		if errors.Is(err, errUnsupportedRuntime) {
			log.Warn("skipping unsupported .NET runtime metrics", "error", err)
			return
		}
		if err != nil && ctx.Err() == nil {
			if !warned {
				log.Warn(".NET GC collection interrupted", "error", err)
				warned = true
			} else {
				log.Debug(".NET GC collection interrupted", "error", err)
			}
		}
		timer := time.NewTimer(c.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// readSession drains concurrently with StopTracing. A deadline bounds both
// control IPC and the final stream drain when the process stops responding.
func (c *SessionManager) readSession(ctx context.Context, session *eventPipeSession, pid uint64, publish func(*runtimemetrics.DotnetRuntimeMetricSnapshot) error) error {
	defer session.stream.Close()
	done := make(chan error, 1)
	go func() {
		var round gcRound
		done <- readRuntimeCounters(session.stream, pid, func(counter runtimeCounter) error {
			snapshot, err := round.observe(counter)
			if err != nil || snapshot == nil {
				return err
			}
			return publish(snapshot)
		})
	}()
	var readErr error
	readFinished := false
	select {
	case readErr = <-done:
		readFinished = true
	case <-ctx.Done():
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	defer cancel()
	deadline, _ := cleanupCtx.Deadline()
	_ = session.stream.SetReadDeadline(deadline)
	stopErr := stopEventPipe(cleanupCtx, session)
	if !readFinished {
		readErr = <-done
	}
	if ctx.Err() != nil {
		if err := errors.Join(readErr, stopErr); err != nil {
			slog.Debug(".NET EventPipe session ended during cancellation",
				"session", session.id, "error", err)
		}
		return ctx.Err()
	}
	if stopErr != nil {
		return errors.Join(readErr, fmt.Errorf("stopping EventPipe: %w", stopErr))
	}
	return readErr
}
