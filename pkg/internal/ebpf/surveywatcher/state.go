package surveywatcher

import (
	"context"
	"sync"
	"time"
)

// Socket evidence flags recorded by the BPF watcher. They mirror the
// SURVEY_SOCK_* defines in bpf/survey_watcher/survey_watcher.c.
const (
	FlagAny uint8 = 1 << iota
	FlagPrivileged
	FlagNonPrivileged
)

// Process identifies one lifetime using OBI's namespace PID identity.
// StartTime is /proc/PID/stat's start time in clock ticks since boot.
type Process struct {
	PID       uint32
	Namespace uint32
	StartTime uint64
	Flags     uint8
}

type Snapshot map[Process]struct{}

// State publishes complete, immutable snapshots. Notifications may coalesce;
// consumers always read the latest snapshot, never a lossy sequence of PID events.
type State struct {
	mu      sync.RWMutex
	current Snapshot
	changes chan struct{}
}

func NewState() *State {
	return &State{current: Snapshot{}, changes: make(chan struct{}, 1)}
}

func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *State) Changes() <-chan struct{} { return s.changes }

func (s *State) publish(snapshot Snapshot) {
	s.mu.Lock()
	s.current = snapshot
	s.mu.Unlock()

	select {
	case s.changes <- struct{}{}:
	default:
	}
}

// reconcile debounces bursts with a fixed deadline from the first notification.
// Sustained activity cannot postpone a read indefinitely. Periodic reads recover
// map entries even if their ring-buffer notifications were dropped.
func reconcile(ctx context.Context, notifications <-chan struct{}, debounce, recovery time.Duration, read func()) {
	ticker := time.NewTicker(recovery)
	defer ticker.Stop()

	var timer *time.Timer
	var deadline <-chan time.Time

	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-notifications:
			if !ok {
				notifications = nil
				continue
			}

			if deadline == nil {
				timer = time.NewTimer(debounce)
				deadline = timer.C
			}
		case <-deadline:
			deadline = nil
			read()
		case <-ticker.C:
			if timer != nil {
				timer.Stop()
			}

			deadline = nil
			read()
		}
	}
}
