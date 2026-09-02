// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
)

// javaInjectionQueueLen bounds how many discovered JVMs can wait for injection.
// The queue only fills while an attach is stuck, and a dropped target loses Java
// TLS telemetry for that process, nothing else.
const javaInjectionQueueLen = 100

// javaInjectionQueue performs Java agent injections on a single worker
// goroutine, off the discovery loop.
//
// Injection must not run concurrently with another injection: attaching to a
// HotSpot JVM switches the euid/egid of the whole OBI process to the target's
// owner, so two overlapping attaches on processes with different owners would
// run under, and restore, each other's credentials.
type javaInjectionQueue struct {
	log     *slog.Logger
	inject  func(context.Context, javaagent.InjectionTarget) error
	targets chan javaagent.InjectionTarget
	done    chan struct{}
	mu      sync.Mutex
	stopped bool
}

func newJavaInjectionQueue(
	log *slog.Logger,
	inject func(context.Context, javaagent.InjectionTarget) error,
) *javaInjectionQueue {
	return &javaInjectionQueue{
		log:     log,
		inject:  inject,
		targets: make(chan javaagent.InjectionTarget, javaInjectionQueueLen),
		done:    make(chan struct{}),
	}
}

// start launches the worker. Targets are injected one at a time, in the order
// they were discovered.
func (q *javaInjectionQueue) start(ctx context.Context) {
	go func() {
		defer close(q.done)
		defer q.stopAndClosePending()

		for {
			select {
			case <-ctx.Done():
				return
			case target := <-q.targets:
				if !q.injectTarget(ctx, target) {
					return
				}
			}
		}
	}()
}

func (q *javaInjectionQueue) injectTarget(ctx context.Context, target javaagent.InjectionTarget) bool {
	defer func() {
		if err := target.Close(); err != nil {
			q.log.Warn("unable to close java injection target", "pid", target.Pid, "error", err)
		}
	}()

	// A ready target and a cancelled context make both worker select cases
	// eligible. No new attach may start once shutdown has begun.
	if ctx.Err() != nil {
		return false
	}

	if err := q.inject(ctx, target); err != nil {
		q.log.Warn("unable to attach java agent to process, Java TLS telemetry will not work",
			"pid", target.Pid, "error", err)
	}
	return true
}

func (q *javaInjectionQueue) stopAndClosePending() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.stopped = true
	for {
		select {
		case target := <-q.targets:
			if err := target.Close(); err != nil {
				q.log.Warn("unable to close pending java injection target", "pid", target.Pid, "error", err)
			}
		default:
			return
		}
	}
}

// enqueue never blocks. A stuck attach holds the worker for up to the Java
// attach timeout, and process discovery must keep running meanwhile.
//
// Only JVMs are admitted: the queue is bounded, and letting processes the
// injector would ignore consume slots would let unrelated discovery churn
// evict a real JVM while an attach is stuck.
func (q *javaInjectionQueue) enqueue(target javaagent.InjectionTarget) {
	if target.Type != svc.InstrumentableJava {
		_ = target.Close()
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.stopped {
		_ = target.Close()
		q.log.Debug("java injection queue stopped, skipping java agent injection", "pid", target.Pid)
		return
	}

	select {
	case q.targets <- target:
	default:
		_ = target.Close()
		q.log.Warn("java injection queue is full, skipping java agent injection", "pid", target.Pid)
	}
}

// wait joins the worker. The injection in flight observes the cancelled context
// through its own attach deadline, so this returns without waiting for that
// deadline to elapse.
func (q *javaInjectionQueue) wait() {
	<-q.done
}
