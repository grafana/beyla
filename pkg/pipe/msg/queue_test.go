package msg

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/v2/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestNoSubscribers_Blocking(t *testing.T) {
	// test that sender blocked if there are no subscribers
	q := NewQueue[int](ChannelBufferLen(0))
	sent := make(chan int)
	go func() {
		q.Send(1)
		close(sent)
	}()
	select {
	case <-sent:
		t.Fatal("channel should not be closed")
	case <-time.After(5 * time.Millisecond):
		// ok!
	}
}

func TestNoSubscribers_NotBlocking(t *testing.T) {
	// test that sender is not blocked if there are no subscribers
	q := NewQueue[int](ChannelBufferLen(0), NotBlockIfNoSubscribers())
	sent := make(chan int)
	go func() {
		q.Send(1)
		close(sent)
	}()
	testutil.ReadChannel(t, sent, timeout)
	testutil.ChannelEmpty(t, sent, 5*time.Millisecond)
}

func TestMultipleSubscribers(t *testing.T) {
	q := NewQueue[int]()
	ch1 := q.Subscribe()
	ch2 := q.Subscribe()
	go q.Send(123)

	assert.Equal(t, 123, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	testutil.ChannelEmpty(t, ch1, 5*time.Millisecond)
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
}

func TestBypass(t *testing.T) {
	q1 := NewQueue[int]()
	q2 := NewQueue[int]()
	ch2 := q2.Subscribe()
	q1.Bypass(q2)
	go q1.Send(123)
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
}

func TestBypass_SubscribeAfterBypass(t *testing.T) {
	q1 := NewQueue[int]()
	q2 := NewQueue[int]()
	q1.Bypass(q2)
	ch2 := q2.Subscribe()
	go q1.Send(123)
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
}

func TestChainedBypass(t *testing.T) {
	q1 := NewQueue[int]()
	q2 := NewQueue[int]()
	q3 := NewQueue[int]()
	q1.Bypass(q2)
	q2.Bypass(q3)
	ch3 := q3.Subscribe()
	go q1.Send(123)

	assert.Equal(t, 123, testutil.ReadChannel(t, ch3, timeout))
	testutil.ChannelEmpty(t, ch3, 5*time.Millisecond)

}

func TestErrors(t *testing.T) {
	t.Run("can't bypass to itself", func(t *testing.T) {
		q := NewQueue[int]()
		assert.Panics(t, func() {
			q.Bypass(q)
		})
	})
	t.Run("can't bypass to another queue that is already bypassing", func(t *testing.T) {
		q1 := NewQueue[int]()
		q2 := NewQueue[int]()
		q3 := NewQueue[int]()
		q1.Bypass(q2)
		assert.Panics(t, func() {
			q1.Bypass(q3)
		})
	})
	t.Run("can't subscribe to a queue that is bypassing", func(t *testing.T) {
		q1 := NewQueue[int]()
		q2 := NewQueue[int]()
		q1.Bypass(q2)
		assert.Panics(t, func() {
			q1.Subscribe()
		})
	})
}

func TestClose(t *testing.T) {
	q := NewQueue[int](ChannelBufferLen(10))
	ch1, ch2 := q.Subscribe(), q.Subscribe()
	// channels are not closed
	select {
	case <-ch1:
		t.Fatal("channel 1 should not be closed")
	case <-ch2:
		t.Fatal("channel 2 should not be closed")
	default:
		// ok!!
	}
	q.Send(123)
	q.Send(456)
	q.Close()
	// once closed, channels should be closed but might still have contents
	assert.Equal(t, 123, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, ch2, timeout))

	testutil.ChannelEmpty(t, ch1, time.Second)
	testutil.ChannelEmpty(t, ch1, time.Second)
}

func TestClose_Bypassed(t *testing.T) {
	q := NewQueue[int](ChannelBufferLen(10))
	q2 := NewQueue[int](ChannelBufferLen(10))
	q.Bypass(q2)
	ch1, ch2 := q2.Subscribe(), q2.Subscribe()
	// channels are not closed
	select {
	case <-ch1:
		t.Fatal("channel 1 should not be closed")
	case <-ch2:
		t.Fatal("channel 2 should not be closed")
	default:
		// ok!!
	}
	q.Send(123)
	q.Send(456)
	q.Close()
	// once closed, channels should be closed but might still have contents
	assert.Equal(t, 123, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, ch2, timeout))

	testutil.ChannelEmpty(t, ch1, time.Second)
	testutil.ChannelEmpty(t, ch1, time.Second)
}

func TestClose_Errors(t *testing.T) {
	q := NewQueue[int]()
	q.Close()
	t.Run("can't send on closed queue", func(t *testing.T) {
		assert.Panics(t, func() {
			q.Send(123)
		})
	})
	t.Run("can't subscribe on closed queue", func(t *testing.T) {
		assert.Panics(t, func() {
			q.Subscribe()
		})
	})
	t.Run("can't bypass on closed queue", func(t *testing.T) {
		assert.Panics(t, func() {
			q2 := NewQueue[int]()
			q.Bypass(q2)
		})
	})
	t.Run("it's ok re-closing a closed queue", func(t *testing.T) {
		assert.NotPanics(t, q.Close)
	})
}

func TestMarkCloseable(t *testing.T) {
	q := NewQueue[int](ChannelBufferLen(100), ClosingAttempts(3))
	q.Send(1)
	q.MarkCloseable()
	assert.NotPanics(t, func() {
		q.Send(2)
	})
	q.MarkCloseable()
	assert.NotPanics(t, func() {
		q.Send(3)
	})
	q.MarkCloseable()
	t.Run("can't send on closed queue", func(t *testing.T) {
		assert.Panics(t, func() {
			q.Send(4)
		})
	})
}
