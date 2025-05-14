package sync

import (
	"github.com/grafana/beyla/v2/pkg/internal/testutil"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
)

const timeout = 5 * time.Second

func TestQueuePopBlockingIfEmpty(t *testing.T) {
	// GIVEN an empty queue
	q := NewQueue[int]()
	// WHEN popping an element
	available := make(chan int, 30)
	go func() {
		for {
			available <- q.Dequeue()
		}
	}()

	// THEN it blocks until an element is available
	time.Sleep(10 * time.Millisecond)
	select {
	case n := <-available:
		t.Errorf("expected to block, got %d", n)
	default:
		// ok!!
	}

	// WHEN pushing elements
	q.Enqueue(1)

	// THEN it unblocks and elements are returned in order
	assert.Equal(t, 1, testutil.ReadChannel(t, available, timeout))
}

func TestQueueOrdering(t *testing.T) {
	q := NewQueue[int]()

	go func() {
		for i := 0; i < 1000; i++ {
			q.Enqueue(i)
		}
	}()

	for i := 0; i < 1000; i++ {
		assert.Equal(t, i, q.Dequeue())
	}
}

func TestSynchronization(t *testing.T) {
	receivedValues := sync.Map{}
	q := NewQueue[int]()
	for i := 0; i < 1000; i++ {
		cnt := i
		go q.Enqueue(cnt)
	}
	// wait for all the goroutines to finish
	wg := sync.WaitGroup{}
	wg.Add(1000)
	for i := 0; i < 1000; i++ {
		go func() {
			receivedValues.Store(q.Dequeue(), struct{}{})
			wg.Done()
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	testutil.ReadChannel(t, done, timeout)

	for i := 0 ; i < 1000 ; i++ {
		_, ok := receivedValues.Load(i)
		assert.Truef(t, ok, "expected to receive value %d", i)
	}
}
