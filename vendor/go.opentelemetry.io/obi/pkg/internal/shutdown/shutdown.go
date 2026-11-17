// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package shutdown // import "go.opentelemetry.io/obi/pkg/internal/shutdown"

import (
	"context"
	"sync"
	"time"
)

type budgetKey struct{}

const exportHeadroomDivisor = 4

func WithBudget(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return withBudget(ctx, func() time.Duration { return timeout })
}

func WithExportBudget(ctx context.Context, shutdownTimeout func() time.Duration) (context.Context, context.CancelFunc) {
	return withBudget(ctx, func() time.Duration { return ExportBudget(shutdownTimeout()) })
}

func ExportBudget(shutdownTimeout time.Duration) time.Duration {
	return shutdownTimeout - shutdownTimeout/exportHeadroomDivisor
}

func withBudget(ctx context.Context, timeout func() time.Duration) (context.Context, context.CancelFunc) {
	budget, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, func() {
		time.AfterFunc(timeout(), cancel)
	})
	return context.WithValue(ctx, budgetKey{}, budget), func() {
		stop()
		cancel()
	}
}

func Bounded(ctx context.Context, maxTimeout time.Duration) (context.Context, context.CancelFunc) {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), maxTimeout)
	budget, ok := ctx.Value(budgetKey{}).(context.Context)
	if !ok {
		return bounded, cancel
	}
	stop := context.AfterFunc(budget, cancel)
	return bounded, func() {
		stop()
		cancel()
	}
}

type drainsKey struct{}

type Drains struct {
	mu     sync.Mutex
	active int
	idle   chan struct{}
}

func NewDrains() *Drains {
	idle := make(chan struct{})
	close(idle)
	return &Drains{idle: idle}
}

func WithDrains(ctx context.Context, drains *Drains) context.Context {
	return context.WithValue(ctx, drainsKey{}, drains)
}

func RegisterReader(ctx context.Context) func() {
	drains, ok := ctx.Value(drainsKey{}).(*Drains)
	if !ok {
		return func() {}
	}
	drains.begin()
	return sync.OnceFunc(drains.end)
}

func (d *Drains) WaitSettled(grace time.Duration, giveUp <-chan time.Time) {
	for {
		idle := d.Idle()
		select {
		case <-idle:
		case <-giveUp:
			return
		}

		select {
		case <-time.After(grace):
		case <-giveUp:
			return
		}

		if d.Idle() == idle {
			return
		}
	}
}

func (d *Drains) Idle() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.idle
}

func (d *Drains) begin() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active == 0 {
		d.idle = make(chan struct{})
	}
	d.active++
}

func (d *Drains) end() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.active--
	if d.active == 0 {
		close(d.idle)
	}
}
