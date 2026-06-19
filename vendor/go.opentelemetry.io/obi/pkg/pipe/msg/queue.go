// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package msg provides tools for message passing and queues between the different nodes of the OBI pipelines.
package msg // import "go.opentelemetry.io/obi/pkg/pipe/msg"

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

// if a Send operation takes more than this time, we panic informing about a deadlock
// in the user-provide pipeline
const defaultSendTimeout = time.Minute

const unnamed = "(unnamed)"

// bypassMu serializes all the routing changes (Bypass and Subscribe) across every
// queue. These operations only happen while the pipeline is being wired up, so a
// single global lock keeps the bookkeeping trivially correct without complicating
// the Send hot path (which never acquires it).
var bypassMu sync.Mutex

type queueConfig struct {
	channelBufferLen int
	closingAttempts  int
	name             string
	sendTimeout      time.Duration
	panicOnTimeout   bool
	// maps any implementation of imetrics.Reporter's QueueBufferUtilization(subscriber string, ratio float64)
	utilizationGauge func(string, float64)
}

var defaultQueueConfig = queueConfig{
	channelBufferLen: 1,
	closingAttempts:  1,
	name:             unnamed,
	sendTimeout:      defaultSendTimeout,
	panicOnTimeout:   false,
	// default to noop
	utilizationGauge: func(string, float64) {},
}

// QueueOpts allow configuring some operation of a queue
type QueueOpts func(*queueConfig)

// ChannelBufferLen sets the length of the channel buffer for the queue.
func ChannelBufferLen(l int) QueueOpts {
	return func(c *queueConfig) {
		c.channelBufferLen = l
	}
}

// Name sets the name of the queue. Useful for debugging.
func Name(name string) QueueOpts {
	return func(c *queueConfig) {
		c.name = name
	}
}

// SendTimeout sets the timeout for Send operations. This is useful for detecting
// deadlocks derived from a wrong Pipeline construction. It panics if after
// a send operation, the channel is blocked for more than this timeout.
// Some nodes might require too long to initialize. For example the Kubernetes Decorator
// at start, has to download a whole snapshot
func SendTimeout(to time.Duration) QueueOpts {
	return func(c *queueConfig) {
		c.sendTimeout = to
	}
}

// PanicOnSendTimeout configures the queue to panic when a send operation times out.
func PanicOnSendTimeout() QueueOpts {
	return func(c *queueConfig) {
		c.panicOnTimeout = true
	}
}

// ClosingAttempts sets the number of invocations to MarkCloseable before the channel is
// effectively closed.
// This is useful when multiple nodes are sending messages to the same queue, and we want
// to close the queue only when all of them have marked the channel as closeable.
func ClosingAttempts(attempts int) QueueOpts {
	return func(c *queueConfig) {
		c.closingAttempts = attempts
	}
}

func InternalMetrics(p imetrics.Reporter) QueueOpts {
	return func(c *queueConfig) {
		c.utilizationGauge = p.QueueBufferUtilization
	}
}

type dst[T any] struct {
	name  string
	ch    chan T
	gauge func(string, float64)
}

// sink holds the mutable, shared delivery state of a group of queues connected through Bypass.
// When a Queue is bypassed to another Queue, the *sink reference is transferred to the destination.
// So e.g. in a chain of a->b->c->d bypassing queues, invoking a.Send will directly deliver
// the message to d's subscribers.
type sink[T any] struct {
	mt sync.Mutex
	// cfg is the configuration of the queue that owns this sink (the final destination of the
	// bypass group). It drives the channel buffer length and the send timeout behavior.
	cfg *queueConfig
	// dsts are the subscriber channels of all the queues in the group.
	dsts []dst[T]
	// members are all the queues currently routing into this sink. When two groups merge, the
	// members of the source group are re-pointed here, so every queue always references the
	// current destination sink directly.
	members []*Queue[T]
	closed  atomic.Bool

	sendTimeout *time.Timer
	logger      *slog.Logger
}

// Queue is a simple message queue that allows sending messages to multiple subscribers.
// It also allows bypassing messages to other queues, so that a message sent to one queue
// can be received by subscribers of another queue.
// If a message is sent to a queue that has no subscribers, it will not block the sender and the
// message will be lost. This is by design, as the queue is meant to be used for fire-and-forget
type Queue[T any] struct {
	cfg *queueConfig

	// sink points to the shared delivery state of this queue's bypass chain. It is never nil and,
	// after one or more Bypass calls, points directly to the final destination of the chain.
	sink *sink[T]

	// routeNames is the sequence of queue names from this queue to its sink's destination,
	// used only for building human-readable diagnostics about blocked send paths.
	routeNames []string

	// bypassed is set the first time Bypass is invoked on this queue, to enforce that a queue
	// can only bypass to a single destination.
	bypassed bool

	remainingClosers int
}

// NewQueue creates a new Queue instance with the given options.
func NewQueue[T any](opts ...QueueOpts) *Queue[T] {
	cfg := defaultQueueConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	// if channel capacity is set to zero, disable capacity ratio metrics to avoid divisions by zero
	if cfg.channelBufferLen <= 0 {
		cfg.utilizationGauge = func(string, float64) {}
	}

	q := &Queue[T]{
		cfg:              &cfg,
		routeNames:       []string{cfg.name},
		remainingClosers: cfg.closingAttempts,
	}
	q.sink = &sink[T]{
		cfg:         &cfg,
		members:     []*Queue[T]{q},
		sendTimeout: time.NewTimer(cfg.sendTimeout),
		logger:      slog.With("queueName", cfg.name),
	}
	return q
}

// SendCtx sends a message to all subscribers of this queue, and interrupts the operation if the
// passed context is canceled.
// If there are no subscribers at the moment of sending the message, the message will be lost.
// If there are subscribers, the message will be stored on their respective internal channels
// until it is read by the subscribers.
// If a subscriber is blocked, its internal channel might be full and
// the SendCtx operation would block for all the subscribers until all the internal channels
// of the Queue room for a new message.
func (q *Queue[T]) SendCtx(ctx context.Context, o T) {
	q.assertNotClosed()
	q.sink.send(ctx, o, q.routeNames)
}

// Send is analogous to SendCtx(context.Background()).
// This operation could get into a deadlock if during the Send operation, the subscriber node stops
// reading messages (e.g. during OBI shutdown). So it is highly recommended to use SendCtx instead.
//
// Deprecated: use SendCtx instead.
func (q *Queue[T]) Send(o T) {
	q.assertNotClosed()
	q.sink.send(context.Background(), o, q.routeNames)
}

// send delivers the message to all the subscribers of the sink. route is the path of queue names
// that lead to this sink, used only to build diagnostics when a subscriber blocks.
func (s *sink[T]) send(ctx context.Context, o T, route []string) {
	// Subscribe appends to s.dsts under s.mt. Snapshot the subscriber list here so this Send
	// iterates a stable copy: concurrent Subscribe is safe and we avoid racing on the slice
	// header. Do not hold the mutex while writing to subscriber channels (Send can block).
	s.mt.Lock()
	if len(s.dsts) == 0 {
		s.mt.Unlock()
		// this can happen in dead paths (which are valid for disabled pipeline branches),
		// exiting early to save timeout management
		return
	}
	dsts := make([]dst[T], len(s.dsts))
	copy(dsts, s.dsts)
	s.mt.Unlock()

	if s.cfg.panicOnTimeout {
		// instead of directly panicking in sendTimeout, we first warn at 90% sendTimeout,
		// to get logged about other blocked senders before panicking
		s.sendTimeout.Reset(9 * s.cfg.sendTimeout / 10)
	} else {
		s.sendTimeout.Reset(s.cfg.sendTimeout)
	}
	var blocked []dst[T]
	for _, d := range dsts {
		// report channel len/capacity ratio metrics
		d.gauge(d.name, float64(len(d.ch)+1)/float64(cap(d.ch)))
		select {
		case <-ctx.Done():
			return
		case d.ch <- o:
			// good!
		case <-s.sendTimeout.C:
			s.logger.Warn("an internal queue seems to be blocked. You might need to change "+
				"some of the following configuration options: OTEL_EBPF_OTLP_TRACES_BATCH_MAX_SIZE, "+
				"OTEL_EBPF_OTLP_TRACES_QUEUE_SIZE, OTEL_EBPF_CHANNEL_BUFFER_LEN, OTEL_EBPF_CHANNEL_SEND_TIMEOUT, "+
				"OTEL_EBPF_BPF_BATCH_LENGTH, OTEL_EBPF_BPF_BATCH_TIMEOUT",
				slog.Duration("timeout", s.cfg.sendTimeout),
				slog.Int("queueLen", len(d.ch)),
				slog.Int("queueCap", cap(d.ch)),
				slog.String("sendPath", sendPath(route, d.name)),
				slog.String("subscriber", d.name),
			)
			blocked = append(blocked, d)
		}
	}

	if !s.cfg.panicOnTimeout {
		// if we don't configure the queue to panic on timeout, we wait
		// for the messages to be delivered
		for _, d := range blocked {
			select {
			case <-ctx.Done():
				return
			case d.ch <- o:
				// good!
			}
		}
	} else {
		// if we confirm that the blocker candidates are actually blocked, we panic
		s.sendTimeout.Reset(s.cfg.sendTimeout / 10)
		for _, d := range blocked {
			select {
			case <-ctx.Done():
				return
			case d.ch <- o:
				// good!
			case <-s.sendTimeout.C:
				panic(fmt.Sprintf("sending through queue path %s. Subscriber channel %s is blocked",
					sendPath(route, d.name), d.name))
			}
		}
	}
}

type subscribeOpts struct {
	subscriber string
}

type SubscribeOpt func(*subscribeOpts)

// SubscriberName helps debugging any blocked channel reader
func SubscriberName(nodeName string) SubscribeOpt {
	return func(o *subscribeOpts) {
		o.subscriber = nodeName
	}
}

// Subscribe to this queue. This will return a channel that will receive messages.
// It's important to notice that, if Subscribe is invoked after Send, the sent message
// will be lost.
// Concurrent invocations to Subscribe and Bypass are thread-safe between them, so you can be
// sure that any subscriber will get its own effective channel. Send snapshots the subscriber list
// under the same mutex as Subscribe, so concurrent Subscribe and Send do not race; a Send may still
// not deliver to a subscriber that Subscribe'd immediately after the snapshot (that subscriber
// misses that message).
func (q *Queue[T]) Subscribe(options ...SubscribeOpt) <-chan T {
	opts := subscribeOpts{subscriber: unnamed}
	for _, opt := range options {
		opt(&opts)
	}

	// hold bypassMu so q.sink can't be re-pointed by a concurrent Bypass while we subscribe to it
	bypassMu.Lock()
	defer bypassMu.Unlock()
	q.assertNotClosed()

	s := q.sink
	// this mutex is also needed so we don't have race conditions in Send's copy(dsts, s.dsts)
	s.mt.Lock()
	defer s.mt.Unlock()
	ch := make(chan T, s.cfg.channelBufferLen)
	s.dsts = append(s.dsts, dst[T]{
		ch:    ch,
		name:  opts.subscriber,
		gauge: s.cfg.utilizationGauge,
	})
	return ch
}

// Bypass allows this queue to bypass messages to another queue. This means that
// messages sent to this queue will also be sent to the other queue.
// A given queue can only Bypass once, but multiple queues can bypass to the same destination.
// This operation does not control for graph cycles. It might result in an internal mutex deadlock.
func (q *Queue[T]) Bypass(to *Queue[T]) {
	if q == to {
		panic(q.cfg.name + ": this queue can't bypass to itself")
	}

	bypassMu.Lock()
	defer bypassMu.Unlock()
	q.assertNotClosed()
	if q.bypassed {
		panic(fmt.Sprintf("queue %s is already bypassing data", q.cfg.name))
	}
	q.bypassed = true

	srcSink := q.sink
	dstSink := to.sink
	if srcSink == dstSink {
		// q and to already belong to the same bypass group: nothing to merge
		return
	}

	srcSink.mt.Lock()
	defer srcSink.mt.Unlock()
	dstSink.mt.Lock()
	defer dstSink.mt.Unlock()

	// re-point every queue of the source group to the destination sink, so future Sends and
	// Subscribes reach the destination directly, and extend their diagnostic route with to's route
	for _, m := range srcSink.members {
		m.sink = dstSink
		m.routeNames = append(m.routeNames, to.routeNames...)
	}

	// move all the subscribers of the source group into the destination group
	dstSink.dsts = append(dstSink.dsts, srcSink.dsts...)
	srcSink.dsts = nil

	dstSink.members = append(dstSink.members, srcSink.members...)
	srcSink.members = nil

	// the source sink is no longer a delivery point: stop its now-orphaned timer
	if srcSink.sendTimeout != nil {
		srcSink.sendTimeout.Stop()
		srcSink.sendTimeout = nil
	}
}

// Close all the subscribers of this queue. This will close all the channels of the queue's
// bypass group.
func (q *Queue[T]) Close() {
	bypassMu.Lock()
	s := q.sink
	bypassMu.Unlock()

	s.mt.Lock()
	defer s.mt.Unlock()
	s.close()
}

// MarkCloseable decreases the internal counter of submitters, and if it reaches 0,
// (meaning that all senders have closed their channels) it will close the queue.
// This method is useful for multiple nodes sending messages to the same queue, and
// willing to close it only when all
func (q *Queue[T]) MarkCloseable() {
	bypassMu.Lock()
	q.remainingClosers--
	doClose := q.remainingClosers <= 0
	s := q.sink
	bypassMu.Unlock()

	if !doClose {
		return
	}
	s.mt.Lock()
	defer s.mt.Unlock()
	s.close()
}

// close stops the send timer and closes all the subscriber channels of the sink.
// It must be invoked while holding s.mt.
func (s *sink[T]) close() {
	if s.closed.Swap(true) {
		return
	}
	if s.sendTimeout != nil {
		s.sendTimeout.Stop()
	}
	for _, d := range s.dsts {
		close(d.ch)
	}
	s.dsts = nil
}

func (q *Queue[T]) assertNotClosed() {
	if q.sink.closed.Load() {
		panic(q.cfg.name + ": queue is closed")
	}
}

// sendPath renders the diagnostic path of a message, from its origin queue to the blocked
// subscriber, e.g. "src->middle->dst->subscriber".
func sendPath(route []string, subscriber string) string {
	sb := strings.Builder{}
	for _, name := range route {
		sb.WriteString(name)
		sb.WriteString("->")
	}
	sb.WriteString(subscriber)
	return sb.String()
}
