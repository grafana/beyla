package sync

import (
"sync"
)

type Queue[T any] struct {
	data  []T
	mutex sync.Mutex
	cond  *sync.Cond
}

func NewQueue[T any]() *Queue[T] {
	q := &Queue[T]{}
	q.cond = sync.NewCond(&q.mutex)
	return q
}

func (queue *Queue[T]) Enqueue(item T) {
	queue.mutex.Lock()
	queue.data = append(queue.data, item)
	queue.cond.Signal() // Wake up one waiting goroutine
	queue.mutex.Unlock()
}

func (queue *Queue[T]) Dequeue() T {
	queue.mutex.Lock()
	for len(queue.data) == 0 {
		queue.cond.Wait()
	}
	item := queue.data[0]
	queue.data = queue.data[1:]
	queue.mutex.Unlock()
	return item
}
