// Package msg provides tools for message passing and queues between the different nodes of the Beyla pipelines.
package msg

import (
	"sync"
	"sync/atomic"
)

type queueConfig struct {
	channelBufferLen       int
	discardIfNoSubscribers bool
}

var defaultQueueConfig = queueConfig{
	channelBufferLen:       1,
	discardIfNoSubscribers: false,
}

// QueueOpts allow configuring some operation of a queue
type QueueOpts func(*queueConfig)

// ChannelBufferLen sets the length of the channel buffer for the queue.
func ChannelBufferLen(l int) QueueOpts {
	return func(c *queueConfig) {
		c.channelBufferLen = l
	}
}

// NotBlockIfNoSubscribers will prevent the Send operation to block when there are
// no subscribers to the channel.
// This is useful to define connections to destination nodes that are optional and
// might not be instantiated.
func NotBlockIfNoSubscribers() QueueOpts {
	return func(c *queueConfig) {
		c.discardIfNoSubscribers = true
	}
}

// Queue is a simple message queue that allows sending messages to multiple subscribers.
// It also allows bypassing messages to other queues, so that a message sent to one queue
// can be received by subscribers of another queue.
// If a message is sent to a queue that has no subscribers, it will not block the sender and the
// message will be lost. This is by design, as the queue is meant to be used for fire-and-forget
type Queue[T any] struct {
	mt  sync.Mutex
	cfg *queueConfig

	// in blocking channels, dsts will be at least 1 even if subscribers are 0
	// this channel will hold submitted data at least until someone subscribes and
	// reads it. This can block the sender if no one subscribes to the channel
	subscribers int
	dsts        []chan T

	// double-linked list of bypassing queues
	// For simplicity, a Queue instance:
	// - can't bypass to a queue and having other dsts
	// - can only bypass to a single queue, despite multiple queues can bypass to it
	bypassTo *Queue[T]
	closed   atomic.Bool
}

// NewQueue creates a new Queue instance with the given options.
func NewQueue[T any](opts ...QueueOpts) *Queue[T] {
	cfg := defaultQueueConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	var dsts []chan T
	if !cfg.discardIfNoSubscribers {
		dsts = []chan T{make(chan T, cfg.channelBufferLen)}
	}
	return &Queue[T]{cfg: &cfg, dsts: dsts}
}

func (q *Queue[T]) config() *queueConfig {
	if q.cfg == nil {
		return &defaultQueueConfig
	}
	return q.cfg
}

// Send a message to all subscribers of this queue.
// If there are no subscribers and the internal channel is full,
// the sender might block unless the Queue has been instantiated
// with the NotBlockIfNoSubscribers option. In that case,
// the message will be lost and the sender will not be blocked.
func (q *Queue[T]) Send(o T) {
	q.assertNotClosed()
	if q.bypassTo != nil {
		q.bypassTo.Send(o)
		return
	}
	for _, d := range q.dsts {
		d <- o
	}
}

// Subscribe to this queue. This will return a channel that will receive messages.
// It's important to notice that, if Subscribe is invoked after Send, the sent message
// will be lost, or forwarded to other subscribed but not to the channel resulting from the
// last invocation.
// You can't subscribe to a queue that is bypassing to another queue.
// Concurrent invocations to Subscribe and Bypass are thread-safe between them, so you can be
// sure that any subscriber will get its own effective channel. But invocations to Subscribe are not
// thread-safe with the Send method. This means that concurrent invocations to Subscribe and Send might
// result in few initial lost messages.
func (q *Queue[T]) Subscribe() <-chan T {
	q.assertNotClosed()
	q.mt.Lock()
	defer q.mt.Unlock()
	q.assertNotBypassing()

	// might be that subscribers <= len(dsts), for example when the queue is new
	// and has a channel to block sender before subscribers are added
	q.subscribers++
	if q.subscribers > len(q.dsts) {
		q.dsts = append(q.dsts, make(chan T, q.config().channelBufferLen))
	}
	return q.dsts[q.subscribers-1]
}

// Bypass allows this queue to bypass messages to another queue. This means that
// messages sent to this queue will also be sent to the other queue.
// This operation is not thread-safe and does not control for graph cycles.
func (q *Queue[T]) Bypass(to *Queue[T]) {
	q.assertNotClosed()
	q.mt.Lock()
	defer q.mt.Unlock()
	if q == to {
		panic("this queue can't bypass to itself")
	}
	q.assertNotBypassing()
	q.bypassTo = to
}

// Close all the subscribers of this queue. This will close all the channels
// or will close the bypassed channel
func (q *Queue[T]) Close() {
	q.closed.Store(true)
	q.mt.Lock()
	defer q.mt.Unlock()
	if q.bypassTo != nil {
		q.bypassTo.Close()
	} else {
		for _, d := range q.dsts {
			close(d)
		}
		q.dsts = nil
	}
}

func (q *Queue[T]) assertNotBypassing() {
	if q.bypassTo != nil {
		panic("queue already bypassing data to another queue")
	}
}

func (q *Queue[T]) assertNotClosed() {
	if q.closed.Load() {
		panic("queue is closed")
	}
}
