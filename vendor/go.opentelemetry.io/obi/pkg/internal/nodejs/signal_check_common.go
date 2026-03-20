// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

type signalCheckResult int

const (
	signalCheckNotFound signalCheckResult = iota // no SIGUSR1 handler detected
	signalCheckFound                             // SIGUSR1 handler detected
	signalCheckFailed                            // detection failed (e.g. stripped symbols)
)
