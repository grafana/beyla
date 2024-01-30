//go:build !linux

package ifaces

import (
	"context"
)

type Watcher struct{}

func NewWatcher(_ int) *Watcher {
	return &Watcher{}
}

func (w *Watcher) Subscribe(ctx context.Context) (<-chan Event, error) {
	return nil, nil
}
