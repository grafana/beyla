// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"context"
	"time"

	"golang.org/x/sys/unix"
)

// SignalDisposition is what the kernel would do with a signal sent to a process.
type SignalDisposition int

const (
	// SignalDispositionUnknown means the signal masks could not be read.
	SignalDispositionUnknown SignalDisposition = iota
	// SignalDispositionHandled means the signal is caught or ignored.
	SignalDispositionHandled
	// SignalDispositionFatal means the default action terminates the process.
	SignalDispositionFatal
)

const dispositionInterval = 10 * time.Millisecond

// AwaitSignalDisposition waits for signal to stop being fatal to the process,
// which covers the window after exec in which a runtime has not yet installed
// its handler: a process discovered at exec time is otherwise judged on a state
// that clears on its own. A target that exits ends the wait rather than being
// polled to the deadline.
//
// Cancellation reports Unknown: shutdown says nothing about the target.
func (p *ProcessHandle) AwaitSignalDisposition(
	ctx context.Context,
	signal unix.Signal,
	wait time.Duration,
) SignalDisposition {
	deadline := time.Now().Add(wait)

	for {
		disposition := p.SignalDisposition(signal)

		if disposition != SignalDispositionFatal ||
			time.Now().After(deadline) ||
			p.Alive() != nil {
			if ctx.Err() != nil {
				return SignalDispositionUnknown
			}

			return disposition
		}

		select {
		case <-ctx.Done():
			return SignalDispositionUnknown
		case <-time.After(dispositionInterval):
		}
	}
}
