// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

type signalCheckResult int

const (
	signalCheckNotFound signalCheckResult = iota // no SIGUSR1 handler detected
	signalCheckFound                             // SIGUSR1 handler detected
	signalCheckFailed                            // detection failed (e.g. stripped symbols)
)

type signalDisposition int

const (
	signalDispositionUnknown signalDisposition = iota // the kernel's signal mask could not be read
	signalDispositionHandled                          // SIGUSR1 is caught or ignored, so it cannot terminate the process
	signalDispositionFatal                            // SIGUSR1 is neither caught nor ignored: the default action terminates
)
