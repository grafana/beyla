// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"slices"
	"sync"
)

const (
	dynamicNotifyBufferSize = 64
	dynamicNotifyPendingMax = dynamicNotifyBufferSize
)

// dynamicBatchNotifier fans out batches of T to subscribers without blocking producers
// on a slow consumer.
type dynamicBatchNotifier[T any] struct {
	subscribers []*dynamicBatchSubscriber[T]

	pending []T
	mu      sync.Mutex
	cond    *sync.Cond
}

type dynamicBatchSubscriber[T any] struct {
	ctx        context.Context
	ch         chan []T
	wake       chan struct{}
	done       chan struct{}
	maxPending int
	mu         sync.Mutex
	pending    []T
}

func newDynamicBatchNotifier[T any]() *dynamicBatchNotifier[T] {
	n := &dynamicBatchNotifier[T]{}
	n.cond = sync.NewCond(&n.mu)
	go n.drain()
	return n
}

func (n *dynamicBatchNotifier[T]) Notify(batch []T) {
	if len(batch) == 0 {
		return
	}
	n.mu.Lock()
	// No live consumers: drop rather than queue forever. New subscribers recover via
	// GetPIDs() / GetK8sWorkloads() snapshots.
	if len(n.subscribers) == 0 {
		n.mu.Unlock()
		return
	}
	n.pending = append(n.pending, batch...)
	n.cond.Signal()
	n.mu.Unlock()
}

func (n *dynamicBatchNotifier[T]) Subscribe() <-chan []T {
	return n.subscribe(context.Background(), dynamicNotifyPendingMax)
}

func (n *dynamicBatchNotifier[T]) SubscribeContext(ctx context.Context) <-chan []T {
	return n.subscribe(ctx, 0)
}

func (n *dynamicBatchNotifier[T]) subscribe(ctx context.Context, maxPending int) <-chan []T {
	subscriber := newDynamicBatchSubscriber[T](ctx, maxPending)
	n.mu.Lock()
	n.subscribers = append(n.subscribers, subscriber)
	n.cond.Signal()
	n.mu.Unlock()

	// Background/TODO have a nil Done channel and never cancel; skip cleanup for those.
	if ctx.Done() != nil {
		go func() {
			<-subscriber.done
			n.removeSubscriber(subscriber)
		}()
	}
	return subscriber.ch
}

func (n *dynamicBatchNotifier[T]) removeSubscriber(subscriber *dynamicBatchSubscriber[T]) {
	n.mu.Lock()
	n.subscribers = slices.DeleteFunc(n.subscribers, func(ch *dynamicBatchSubscriber[T]) bool {
		return ch == subscriber
	})
	if len(n.subscribers) == 0 {
		n.pending = nil
	}
	n.mu.Unlock()
}

func (n *dynamicBatchNotifier[T]) drain() {
	for {
		n.mu.Lock()
		for len(n.pending) == 0 || len(n.subscribers) == 0 {
			n.cond.Wait()
		}
		batch := append([]T(nil), n.pending...)
		n.pending = n.pending[:0]
		subscribers := slices.Clone(n.subscribers)
		n.mu.Unlock()

		for _, subscriber := range subscribers {
			subscriber.notify(batch)
		}
	}
}

func newDynamicBatchSubscriber[T any](ctx context.Context, maxPending int) *dynamicBatchSubscriber[T] {
	if ctx == nil {
		ctx = context.Background()
	}
	s := &dynamicBatchSubscriber[T]{
		ctx:        ctx,
		ch:         make(chan []T, dynamicNotifyBufferSize),
		wake:       make(chan struct{}, 1),
		done:       make(chan struct{}),
		maxPending: maxPending,
	}
	go s.run()
	return s
}

func (s *dynamicBatchSubscriber[T]) notify(batch []T) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	// Queue on the subscriber so a full subscriber channel cannot block notifier fan-out.
	s.mu.Lock()
	for _, item := range batch {
		if s.maxPending > 0 && len(s.pending) == s.maxPending {
			break
		}
		s.pending = append(s.pending, item)
	}
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *dynamicBatchSubscriber[T]) run() {
	defer close(s.done)
	defer close(s.ch)

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
			for {
				batch := s.takePending()
				if len(batch) == 0 {
					break
				}
				select {
				case s.ch <- batch:
				case <-s.ctx.Done():
					return
				}
			}
		}
	}
}

func (s *dynamicBatchSubscriber[T]) takePending() []T {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 {
		return nil
	}

	// Send a stable batch while later notify calls append to a fresh pending queue.
	batch := slices.Clone(s.pending)
	s.pending = nil
	return batch
}

// dynamicEdgePairNotifier is an added/removed pair of batch notifiers (PID signal views).
type dynamicEdgePairNotifier[T any] struct {
	added   *dynamicBatchNotifier[T]
	removed *dynamicBatchNotifier[T]
}

func newDynamicEdgePairNotifier[T any]() *dynamicEdgePairNotifier[T] {
	return &dynamicEdgePairNotifier[T]{
		added:   newDynamicBatchNotifier[T](),
		removed: newDynamicBatchNotifier[T](),
	}
}

func (n *dynamicEdgePairNotifier[T]) notifyAdded(batch []T)   { n.added.Notify(batch) }
func (n *dynamicEdgePairNotifier[T]) notifyRemoved(batch []T) { n.removed.Notify(batch) }

func (n *dynamicEdgePairNotifier[T]) addedNotify() <-chan []T {
	return n.added.Subscribe()
}

func (n *dynamicEdgePairNotifier[T]) addedNotifyContext(ctx context.Context) <-chan []T {
	return n.added.SubscribeContext(ctx)
}

func (n *dynamicEdgePairNotifier[T]) removedNotify() <-chan []T {
	return n.removed.Subscribe()
}

func (n *dynamicEdgePairNotifier[T]) removedNotifyContext(ctx context.Context) <-chan []T {
	return n.removed.SubscribeContext(ctx)
}

// dynamicWakeNotifier fans out payload-free wake signals (e.g. targets-changed rescans).
type dynamicWakeNotifier struct {
	subscribers []*dynamicWakeSubscriber

	pending int
	mu      sync.Mutex
	cond    *sync.Cond
}

type dynamicWakeSubscriber struct {
	ctx  context.Context
	ch   chan struct{}
	wake chan struct{}
	done chan struct{}
	mu   sync.Mutex
	n    int
}

func newDynamicWakeNotifier() *dynamicWakeNotifier {
	n := &dynamicWakeNotifier{}
	n.cond = sync.NewCond(&n.mu)
	go n.drain()
	return n
}

func (n *dynamicWakeNotifier) Notify() {
	n.mu.Lock()
	if len(n.subscribers) == 0 {
		n.mu.Unlock()
		return
	}
	n.pending++
	n.cond.Signal()
	n.mu.Unlock()
}

func (n *dynamicWakeNotifier) Subscribe() <-chan struct{} {
	return n.subscribe(context.Background())
}

func (n *dynamicWakeNotifier) SubscribeContext(ctx context.Context) <-chan struct{} {
	return n.subscribe(ctx)
}

func (n *dynamicWakeNotifier) subscribe(ctx context.Context) <-chan struct{} {
	subscriber := newDynamicWakeSubscriber(ctx)
	n.mu.Lock()
	n.subscribers = append(n.subscribers, subscriber)
	n.cond.Signal()
	n.mu.Unlock()

	// Background/TODO have a nil Done channel and never cancel; skip cleanup for those.
	if ctx.Done() != nil {
		go func() {
			<-subscriber.done
			n.removeSubscriber(subscriber)
		}()
	}
	return subscriber.ch
}

func (n *dynamicWakeNotifier) removeSubscriber(subscriber *dynamicWakeSubscriber) {
	n.mu.Lock()
	n.subscribers = slices.DeleteFunc(n.subscribers, func(ch *dynamicWakeSubscriber) bool {
		return ch == subscriber
	})
	if len(n.subscribers) == 0 {
		n.pending = 0
	}
	n.mu.Unlock()
}

func (n *dynamicWakeNotifier) drain() {
	for {
		n.mu.Lock()
		for n.pending == 0 || len(n.subscribers) == 0 {
			n.cond.Wait()
		}
		count := n.pending
		n.pending = 0
		subscribers := slices.Clone(n.subscribers)
		n.mu.Unlock()

		for _, subscriber := range subscribers {
			subscriber.notify(count)
		}
	}
}

func newDynamicWakeSubscriber(ctx context.Context) *dynamicWakeSubscriber {
	if ctx == nil {
		ctx = context.Background()
	}
	s := &dynamicWakeSubscriber{
		ctx:  ctx,
		ch:   make(chan struct{}, dynamicNotifyBufferSize),
		wake: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *dynamicWakeSubscriber) notify(count int) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	s.mu.Lock()
	s.n += count
	if s.n > dynamicNotifyPendingMax {
		s.n = dynamicNotifyPendingMax
	}
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *dynamicWakeSubscriber) run() {
	defer close(s.done)
	defer close(s.ch)

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
			for s.sendOne() {
			}
		}
	}
}

func (s *dynamicWakeSubscriber) sendOne() bool {
	s.mu.Lock()
	if s.n == 0 {
		s.mu.Unlock()
		return false
	}
	s.n--
	s.mu.Unlock()

	select {
	case s.ch <- struct{}{}:
		return true
	case <-s.ctx.Done():
		return false
	}
}
