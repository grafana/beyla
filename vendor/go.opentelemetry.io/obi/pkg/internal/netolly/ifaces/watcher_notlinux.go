// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ifaces // import "go.opentelemetry.io/obi/pkg/internal/netolly/ifaces"

import (
	"context"
)

type Watcher struct{}

func NewWatcher(_ int) *Watcher {
	return &Watcher{}
}

func (w *Watcher) Subscribe(_ context.Context) (<-chan Event, error) {
	return nil, nil
}
