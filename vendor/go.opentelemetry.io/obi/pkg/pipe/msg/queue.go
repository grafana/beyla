// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package msg provides tools for message passing and queues between the different nodes of the Beyla pipelines.
package msg // import "go.opentelemetry.io/obi/pkg/pipe/msg"

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// if a Send operation takes more than this time, we panic informing about a deadlock
// in the user-provide pipeline
const defaultSendTimeout = time.Minute

const unnamed = "(unnamed)"

type queueConfig struct {
	channelBufferLen int
	closingAttempts  int
	name             string
	sendTimeout      time.Duration
	panicOnTimeout   bool
}

var defaultQueueConfig = queueConfig{
	channelBufferLen: 1,
	closingAttempts:  1,
	name:             unnamed,
	sendTimeout:      defaultSendTimeout,
	panicOnTimeout:   false,
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

type dst[T any] struct {
	name string
	ch   chan T
}

// Queue is a simple message queue that allows sending messages to multiple subscribers.
// It also allows bypassing messages to other queues, so that a message sent to one queue
// can be received by subscribers of another queue.
// If a message is sent to a queue that has no subscribers, it will not block the sender and the
// message will be lost. This is by design, as the queue is meant to be used for fire-and-forget
type Queue[T any] struct {
	mt  sync.Mutex
	cfg *queueConfig

	dsts             []dst[T]
	remainingClosers int

	// linked list of bypassing queues
	// For simplicity, a Queue instance can only bypass to a single queue, despite multiple queues can bypass to it
	bypassTo *Queue[T]
	closed   atomic.Bool

	sendTimeout *time.Timer
	logger      *slog.Logger
}

// NewQueue creates a new Queue instance with the given options.
func NewQueue[T any](opts ...QueueOpts) *Queue[T] {
	cfg := defaultQueueConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Queue[T]{
		cfg:              &cfg,
		remainingClosers: cfg.closingAttempts,
		sendTimeout:      time.NewTimer(cfg.sendTimeout),
		logger:           slog.With("queueName", cfg.name),
	}
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
	q.chainedSend(ctx, o, []string{q.cfg.name})
}

// Send is analogous to SendCtx(context.Background()).
// This operation could get into a deadlock if during the Send operation, the subscriber node stops
// reading messages (e.g. during OBI shutdown). So it is highly recommended to use SendCtx instead.
// Deprecated: use SendCtx instead.
func (q *Queue[T]) Send(o T) {
	q.chainedSend(context.Background(), o, []string{q.cfg.name})
}

func (q *Queue[T]) chainedSend(ctx context.Context, o T, bypassPath []string) {
	q.assertNotClosed()
	if q.bypassTo != nil {
		q.bypassTo.chainedSend(ctx, o, append(bypassPath, q.bypassTo.cfg.name))
		return
	}

	// this can happen in dead paths (which are valid for disabled pipeline branches),
	// exiting early to save timeout management
	if len(q.dsts) == 0 {
		return
	}

	if q.cfg.panicOnTimeout {
		// instead of directly panicking in sendTimeout, we first warn at 90% sendTimeout,
		// to get logged about other blocked senders before panicking
		q.sendTimeout.Reset(9 * q.cfg.sendTimeout / 10)
	} else {
		q.sendTimeout.Reset(q.cfg.sendTimeout)
	}
	var blocked []dst[T]
	for _, d := range q.dsts {
		select {
		case <-ctx.Done():
			return
		case d.ch <- o:
			// good!
		case <-q.sendTimeout.C:
			q.logger.Warn("an internal queue seems to be blocked. You might need to change "+
				"some of the following configuration options: OTEL_EBPF_OTLP_TRACES_MAX_QUEUE_SIZE, "+
				"OTEL_EBPF_CHANNEL_BUFFER_LEN, OTEL_EBPF_CHANNEL_SEND_TIMEOUT, "+
				"OTEL_EBPF_BPF_BATCH_LENGTH, OTEL_EBPF_BPF_BATCH_TIMEOUT",
				slog.Duration("timeout", q.cfg.sendTimeout),
				slog.Int("queueLen", len(d.ch)),
				slog.Int("queueCap", cap(d.ch)),
				slog.String("sendPath", strings.Join(bypassPath, "->")),
				slog.String("subscriber", d.name),
			)
			blocked = append(blocked, d)
		}
	}

	if !q.cfg.panicOnTimeout {
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
		q.sendTimeout.Reset(q.cfg.sendTimeout / 10)
		for _, d := range blocked {
			select {
			case <-ctx.Done():
				return
			case d.ch <- o:
				// good!
			case <-q.sendTimeout.C:
				panic(fmt.Sprintf("sending through queue path %s. Subscriber channel %s is blocked",
					strings.Join(bypassPath, "->"), d.name))
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

func withRawOpts(opts subscribeOpts) SubscribeOpt {
	return func(o *subscribeOpts) {
		*o = opts
	}
}

// Subscribe to this queue. This will return a channel that will receive messages.
// It's important to notice that, if Subscribe is invoked after Send, the sent message
// will be lost.
// Concurrent invocations to Subscribe and Bypass are thread-safe between them, so you can be
// sure that any subscriber will get its own effective channel. But invocations to Subscribe are not
// thread-safe with the Send method. This means that concurrent invocations to Subscribe and Send might
// result in few initial lost messages.
func (q *Queue[T]) Subscribe(options ...SubscribeOpt) <-chan T {
	q.assertNotClosed()
	q.mt.Lock()
	defer q.mt.Unlock()

	opts := subscribeOpts{subscriber: unnamed}
	for _, opt := range options {
		opt(&opts)
	}

	if q.bypassTo != nil {
		return q.bypassTo.Subscribe(withRawOpts(opts))
	}

	ch := make(chan T, q.cfg.channelBufferLen)
	q.dsts = append(q.dsts, dst[T]{ch: ch, name: opts.subscriber})
	return ch
}

// Bypass allows this queue to bypass messages to another queue. This means that
// messages sent to this queue will also be sent to the other queue.
// This operation does not control for graph cycles. It might result in an internal mutex deadlock.
func (q *Queue[T]) Bypass(to *Queue[T]) {
	q.assertNotClosed()
	q.mt.Lock()
	defer q.mt.Unlock()
	if q == to {
		panic(q.cfg.name + ": this queue can't bypass to itself")
	}
	q.assertNotBypassing()

	q.bypassTo = to
	// will copy all the subscribers of the queue to the last queue in the
	// bypassing chain
	last := to
	last.mt.Lock()
	for last.bypassTo != nil {
		l := last
		last = last.bypassTo
		last.mt.Lock()
		l.mt.Unlock()
	}
	last.dsts = append(last.dsts, q.dsts...)
	q.dsts = nil
	q.sendTimeout = nil
	last.mt.Unlock()
}

// Close all the subscribers of this queue. This will close all the channels
// or will close the bypassed channel
func (q *Queue[T]) Close() {
	q.mt.Lock()
	defer q.mt.Unlock()
	if q.sendTimeout != nil {
		q.sendTimeout.Stop()
	}
	q.close()
}

// MarkCloseable decreases the internal counter of submitters, and if it reaches 0,
// (meaning that all senders have closed their channels) it will close the queue.
// This method is useful for multiple nodes sending messages to the same queue, and
// willing to close it only when all
func (q *Queue[T]) MarkCloseable() {
	q.mt.Lock()
	defer q.mt.Unlock()
	q.remainingClosers--
	if q.remainingClosers <= 0 {
		q.close()
	}
}

func (q *Queue[T]) close() {
	if q.closed.Swap(true) {
		return
	}
	if q.bypassTo != nil {
		q.bypassTo.Close()
	} else {
		for _, d := range q.dsts {
			close(d.ch)
		}
		q.dsts = nil
	}
}

func (q *Queue[T]) assertNotBypassing() {
	if q.bypassTo != nil {
		panic(fmt.Sprintf("queue %s already bypassing data to queue %s", q.cfg.name, q.bypassTo.cfg.name))
	}
}

func (q *Queue[T]) assertNotClosed() {
	if q.closed.Load() {
		panic(q.cfg.name + ": queue is closed")
	}
}
