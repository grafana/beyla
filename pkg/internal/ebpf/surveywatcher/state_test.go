package surveywatcher

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateCoalescesNotificationsWithoutLosingSnapshot(t *testing.T) {
	s := NewState()
	s.publish(Snapshot{{PID: 1, StartTime: 10}: {}})
	s.publish(Snapshot{{PID: 1, StartTime: 10}: {}, {PID: 2, StartTime: 20}: {}})
	<-s.Changes()
	require.Len(t, s.Snapshot(), 2)
	select {
	case <-s.Changes():
		t.Fatal("expected coalesced notification")
	default:
	}
	s.publish(Snapshot{})
	<-s.Changes()
	assert.Empty(t, s.Snapshot(), "exits must be reflected in the next snapshot")
}

func TestReconcileDebouncesWithoutStarvation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		notifications := make(chan struct{}, 100)
		reads := 0
		go reconcile(ctx, notifications, 250*time.Millisecond, 5*time.Second, func() { reads++ })
		synctest.Wait()
		for range 5 {
			for range 20 {
				notifications <- struct{}{}
			}
			synctest.Wait()
			time.Sleep(50 * time.Millisecond)
		}
		synctest.Wait()
		assert.Equal(t, 1, reads, "continuous traffic must not reset the first notification's deadline")
		notifications <- struct{}{}
		synctest.Wait()
		time.Sleep(250 * time.Millisecond)
		synctest.Wait()
		assert.Equal(t, 2, reads)
		cancel()
		synctest.Wait()
	})
}

func TestReconcileRecoversWithoutNotifications(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		notifications := make(chan struct{})
		reads := 0
		go reconcile(ctx, notifications, 250*time.Millisecond, 5*time.Second, func() { reads++ })
		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		assert.Equal(t, 1, reads, "a lost ring event must not hide map entries")
		close(notifications)
		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		assert.Equal(t, 2, reads, "reader failure must retain periodic recovery")
		cancel()
		synctest.Wait()
		time.Sleep(10 * time.Second)
		assert.Equal(t, 2, reads, "cancellation must stop reads")
	})
}
