// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import "golang.org/x/sys/unix"

// SignalDisposition is a no-op on non-Linux platforms.
func (*ProcessHandle) SignalDisposition(unix.Signal) SignalDisposition {
	return SignalDispositionHandled
}
