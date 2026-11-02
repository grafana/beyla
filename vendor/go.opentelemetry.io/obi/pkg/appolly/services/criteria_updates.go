// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"context"
	"errors"
	"sync"
)

// CriteriaUpdates coordinates replacement criteria with the process matcher and watcher.
// Selectors passed here must remain immutable while OBI is running.
type CriteriaUpdates struct {
	mu       sync.RWMutex
	include  []Selector
	exclude  []Selector
	requests chan CriteriaUpdate
	changed  chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

type CriteriaUpdate struct {
	Context context.Context
	Include []Selector
	Exclude []Selector
	result  chan error
}

func NewCriteriaUpdates(include, exclude []Selector) *CriteriaUpdates {
	return &CriteriaUpdates{
		include:  include,
		exclude:  exclude,
		requests: make(chan CriteriaUpdate),
		changed:  make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

func (c *CriteriaUpdates) Current() ([]Selector, []Selector) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.include, c.exclude
}

func (c *CriteriaUpdates) Requests() <-chan CriteriaUpdate { return c.requests }
func (c *CriteriaUpdates) Changed() <-chan struct{}        { return c.changed }

func (c *CriteriaUpdates) Replace(ctx context.Context, include, exclude []Selector) error {
	update := CriteriaUpdate{Context: ctx, Include: include, Exclude: exclude, result: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return errors.New("criteria matcher stopped")
	case c.requests <- update:
	}
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err := <-update.result:
		return err
	case <-c.done:
		err = errors.New("criteria matcher stopped")
	}
	// Prefer a completed acknowledgement when cancellation or shutdown also became ready.
	select {
	case result := <-update.result:
		return result
	default:
		return err
	}
}

// Stop notifies callers that the matcher has stopped. It is safe to call repeatedly or concurrently.
func (c *CriteriaUpdates) Stop() {
	c.stopOnce.Do(func() { close(c.done) })
}

// Complete publishes accepted criteria only after the matcher has validated the refresh.
func (c *CriteriaUpdates) Complete(update CriteriaUpdate, err error) {
	if err == nil {
		c.mu.Lock()
		c.include = update.Include
		c.exclude = update.Exclude
		c.mu.Unlock()
		select {
		case c.changed <- struct{}{}:
		default:
		}
	}
	update.result <- err
}
