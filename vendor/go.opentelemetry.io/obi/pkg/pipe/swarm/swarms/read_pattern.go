// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package swarms provides helper functions for operating OBI swarms
package swarms // import "go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"

import (
	"context"
)

// ForEachInput reproduces a ubiquitous pattern for each node in the OBI swarm/pipeline.
// It reads from the input channel and executes the action function on each object.
// It handles two exit conditions:
// - when the context is cancelled
// - when the input channel is closed
// Some nodes might not reproduce this pattern (e.g. they read from multiple channels or need to perform extra
// actions on context cancellation), so it's fine not using this.
func ForEachInput[T any](ctx context.Context, inputCh <-chan T, debug func(string, ...any), action func(obj T)) {
	if debug == nil {
		debug = func(string, ...any) {}
	}
	debug("starting node")
	for {
		select {
		case <-ctx.Done():
			debug("context done, stopping node")
			return
		case obj, ok := <-inputCh:
			if !ok {
				debug("input channel closed, stopping node")
				return
			}
			action(obj)
		}
	}
}
