package msg

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/v2/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestNoSubscribers(t *testing.T) {
	// test that sender is not blocked if there are no subscribers
	q := Queue[int]{}
	sent := make(chan int)
	go func() {
		q.Send(1)
		close(sent)
	}()
	testutil.ReadChannel(t, sent, timeout)
	testutil.ChannelEmpty(t, sent, 5*time.Millisecond)
}

func TestMultipleSubscribers(t *testing.T) {
	q := Queue[int]{}
	ch1 := q.Subscribe()
	ch2 := q.Subscribe()
	go q.Send(123)

	assert.Equal(t, 123, testutil.ReadChannel(t, ch1, timeout))
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	testutil.ChannelEmpty(t, ch1, 5*time.Millisecond)
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
}

func TestBypass(t *testing.T) {
	q1 := Queue[int]{}
	q2 := Queue[int]{}
	ch2 := q2.Subscribe()
	q1.Bypass(&q2)
	go q1.Send(123)
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
}

func TestBypass_SubscribeAfterBypass(t *testing.T) {
	q1 := Queue[int]{}
	q2 := Queue[int]{}
	q1.Bypass(&q2)
	ch2 := q2.Subscribe()
	go q1.Send(123)
	assert.Equal(t, 123, testutil.ReadChannel(t, ch2, timeout))
	testutil.ChannelEmpty(t, ch2, 5*time.Millisecond)
}

func TestChainedBypass(t *testing.T) {
	q1 := Queue[int]{}
	q2 := Queue[int]{}
	q3 := Queue[int]{}
	q1.Bypass(&q2)
	q2.Bypass(&q3)
	ch3 := q3.Subscribe()
	go q1.Send(123)

	assert.Equal(t, 123, testutil.ReadChannel(t, ch3, timeout))
	testutil.ChannelEmpty(t, ch3, 5*time.Millisecond)

}

func TestErrors(t *testing.T) {
	t.Run("can't bypass to itself", func(t *testing.T) {
		q := &Queue[int]{}
		assert.Panics(t, func() {
			q.Bypass(q)
		})
	})
	t.Run("can't bypass to another queue that is already bypassing", func(t *testing.T) {
		q1 := Queue[int]{}
		q2 := Queue[int]{}
		q3 := Queue[int]{}
		q1.Bypass(&q2)
		assert.Panics(t, func() {
			q1.Bypass(&q3)
		})
	})
	t.Run("can't subscribe to a queue that is bypassing", func(t *testing.T) {
		q1 := Queue[int]{}
		q2 := Queue[int]{}
		q1.Bypass(&q2)
		assert.Panics(t, func() {
			q1.Subscribe()
		})
	})
}
