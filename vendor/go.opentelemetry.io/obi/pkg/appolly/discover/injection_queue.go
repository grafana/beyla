// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// injectionTarget is what a queued injection carries: enough to name the
// process in a log, and to release whatever pins it while it waits.
type injectionTarget interface {
	PID() app.PID
	Close() error
}

// injectionSlot serializes injections across every queue holding it. Attaching
// to a HotSpot JVM switches the euid/egid of the whole OBI process, so a
// concurrent injection of any runtime would run under, and restore, the
// target's credentials — costing a Node.js injection its access to
// /proc/<pid>/mem and to the target's network namespace.
//
// It is a channel rather than a mutex so that a worker waiting its turn still
// observes shutdown.
type injectionSlot chan struct{}

func newInjectionSlot() injectionSlot {
	return make(injectionSlot, 1)
}

func (s injectionSlot) acquire(ctx context.Context) bool {
	select {
	case s <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s injectionSlot) release() {
	<-s
}

// injectionQueue performs runtime agent injections on a single worker
// goroutine, off the discovery loop. Every injector waits on its target — a
// JVM's attach handshake, a Node.js runtime's own signal handler and then its
// inspector — and none of that may hold up process discovery.
//
// One queue per runtime keeps the bounds separate, so Node.js churn cannot
// evict a JVM discovered later, while the shared slot keeps the injections
// themselves from overlapping.
type injectionQueue[T injectionTarget] struct {
	log *slog.Logger

	// runtime names the injector in log messages.
	runtime string

	// slot is shared with every other queue, so only one injection anywhere
	// runs at a time.
	slot injectionSlot

	inject func(context.Context, T)

	// admits rejects targets the injector would ignore. The queue is bounded,
	// so letting those consume slots would let unrelated discovery churn evict
	// a real target while an injection is stuck. Nil admits everything.
	admits func(T) bool

	targets chan T
	done    chan struct{}
	mu      sync.Mutex
	stopped bool
}

func newInjectionQueue[T injectionTarget](
	log *slog.Logger,
	runtime string,
	slot injectionSlot,
	depth int,
	inject func(context.Context, T),
	admits func(T) bool,
) *injectionQueue[T] {
	if slot == nil {
		slot = newInjectionSlot()
	}

	return &injectionQueue[T]{
		log:     log,
		runtime: runtime,
		slot:    slot,
		inject:  inject,
		admits:  admits,
		targets: make(chan T, depth),
		done:    make(chan struct{}),
	}
}

// start launches the worker. Targets are injected one at a time, in the order
// they were discovered.
func (q *injectionQueue[T]) start(ctx context.Context) {
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

func (q *injectionQueue[T]) injectTarget(ctx context.Context, target T) bool {
	defer q.closeTarget(target, "dequeued")

	// A ready target and a cancelled context make both worker select cases
	// eligible. No new injection may start once shutdown has begun.
	if ctx.Err() != nil {
		return false
	}

	// Another runtime's injection can hold the slot for as long as its own
	// target makes it wait, and shutdown can arrive in the meantime.
	if !q.slot.acquire(ctx) {
		return false
	}
	defer q.slot.release()

	if ctx.Err() != nil {
		return false
	}

	q.inject(ctx, target)
	return true
}

func (q *injectionQueue[T]) stopAndClosePending() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.stopped = true
	for {
		select {
		case target := <-q.targets:
			q.closeTarget(target, "pending")
		default:
			return
		}
	}
}

func (q *injectionQueue[T]) closeTarget(target T, state string) {
	if err := target.Close(); err != nil {
		q.log.Warn("unable to close injection target",
			"runtime", q.runtime, "state", state, "pid", target.PID(), "error", err)
	}
}

// enqueue never blocks. A slow injection holds the worker for as long as its
// target makes it wait, and process discovery must keep running meanwhile.
func (q *injectionQueue[T]) enqueue(target T) {
	if q.admits != nil && !q.admits(target) {
		q.closeTarget(target, "rejected")
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.stopped {
		q.closeTarget(target, "dropped")
		q.log.Debug("injection queue stopped, skipping agent injection",
			"runtime", q.runtime, "pid", target.PID())
		return
	}

	select {
	case q.targets <- target:
	default:
		q.closeTarget(target, "dropped")
		q.log.Warn("injection queue is full, skipping agent injection",
			"runtime", q.runtime, "pid", target.PID())
	}
}

// wait joins the worker. An injection still deciding whether to proceed
// observes the cancelled context and returns; one that has already reached its
// target runs on its own deadlines, and this waits for them.
func (q *injectionQueue[T]) wait() {
	<-q.done
}
