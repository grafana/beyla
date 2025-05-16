package sync

import (
"sync"
)

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

func (q *Queue[T]) Enqueue(item T) {
	q.mutex.Lock()
	q.append(item)
	q.cond.Signal() // Wake up one waiting goroutine
	q.mutex.Unlock()
}

func (q *Queue[T]) Dequeue() T {
	q.mutex.Lock()
	for q.head == nil {
		q.cond.Wait()
	}
	item := q.remove()
	q.mutex.Unlock()
	return item
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

