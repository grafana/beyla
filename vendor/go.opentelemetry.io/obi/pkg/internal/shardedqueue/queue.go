// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package shardedqueue // import "go.opentelemetry.io/obi/pkg/internal/shardedqueue"

import (
	"context"
	"errors"
	"hash/fnv"
)

var ErrQueueClosed = errors.New("queue closed")

type ShardedQueue[T any] struct {
	queues []chan T
	hash   func(T) string
	done   bool
}

// NewShardedQueue creates a sharded, bounded worker queue.
//
// nWorkers: number of shards
// qLen:     shard channel length
// hash:     sharding function
// worker:   processing function
func NewShardedQueue[T any](
	nWorkers int,
	qLen int,
	hash func(T) string,
	worker func(workerID int, ch <-chan T),
) *ShardedQueue[T] {
	q := &ShardedQueue[T]{
		queues: make([]chan T, nWorkers),
		hash:   hash,
	}

	for i := range nWorkers {
		ch := make(chan T, qLen)
		q.queues[i] = ch
		go worker(i, ch)
	}

	return q
}

// Enqueue adds an item to the appropriate shard.
// Blocks if the shard queue is full.
func (q *ShardedQueue[T]) Enqueue(ctx context.Context, item T) error {
	if q.done {
		return ErrQueueClosed
	}

	h := fnv.New32a()
	h.Write([]byte(q.hash(item)))
	idx := int(h.Sum32() % uint32(len(q.queues)))

	select {
	case <-ctx.Done():
		return ctx.Err()
	case q.queues[idx] <- item:
		return nil
	}
}

func (q *ShardedQueue[T]) Close() {
	if q.done {
		return
	}
	q.done = true

	for _, ch := range q.queues {
		close(ch)
	}
}
