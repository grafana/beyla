// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sync // import "go.opentelemetry.io/obi/pkg/internal/helpers/sync"

import (
	"context"
	"sync"
)

// Queue is a FIFO structure that allows asynchronously enqueuing messages and synchronously dequeuing them.
// The Dequeue operation is blocked until there is any content in the queue.
// You can see a Queue as a channel with infinite capacity where you can keep sending
// elements without getting blocked.
// TODO: can we replace this by channel-based msg.Queue?
type Queue[T any] struct {
	head  *node[T]
	tail  *node[T]
	mutex sync.Mutex
	cond  *sync.Cond
}

type node[T any] struct {
	value T
	next  *node[T]
	prev  *node[T]
}

func NewQueue[T any]() *Queue[T] {
	q := &Queue[T]{}
	q.cond = sync.NewCond(&q.mutex)
	return q
}

// Enqueue adds an element to the queue. This operation never blocks, this means that
// if there isn't any goroutine dequeuing the elements, the queue will grow indefinitely.
func (q *Queue[T]) Enqueue(item T) {
	q.mutex.Lock()
	q.append(item)
	q.cond.Signal() // Wake up one waiting goroutine
	q.mutex.Unlock()
}

// Dequeue retrieves the firs element in the queue. If the queue is empty, Dequeue will
// block the current goroutine until there is any available element.
func (q *Queue[T]) Dequeue() T {
	q.mutex.Lock()
	for q.head == nil {
		q.cond.Wait()
	}
	item := q.remove()
	q.mutex.Unlock()
	return item
}

// DequeueOrDone retrieves the first element in the queue.
// If ctx is cancelled while the queue is empty, it returns (zero, false).
// If an element is available (or becomes available), it returns (element, true).
func (q *Queue[T]) DequeueOrDone(ctx context.Context) (T, bool) {
	// Spawn a waker goroutine: when ctx is cancelled, broadcast on the cond
	// so that any goroutine blocked in cond.Wait() can re-check and exit.
	stopWaker := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			q.mutex.Lock()
			q.cond.Broadcast()
			q.mutex.Unlock()
		case <-stopWaker:
		}
	}()
	defer close(stopWaker)

	q.mutex.Lock()
	for q.head == nil {
		q.cond.Wait()
		if ctx.Err() != nil {
			q.mutex.Unlock()
			var zero T
			return zero, false
		}
	}
	item := q.remove()
	q.mutex.Unlock()
	return item, true
}

func (q *Queue[T]) append(item T) {
	n := node[T]{value: item}
	if q.tail == nil {
		q.tail = &n
		q.head = &n
	} else {
		q.tail.prev = &n
		n.next = q.tail
		q.tail = &n
	}
}

func (q *Queue[T]) remove() T {
	v := q.head
	q.head = v.prev
	if q.head == nil {
		q.tail = nil
	}
	return v.value
}
