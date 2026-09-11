// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"go.opentelemetry.io/obi/pkg/internal/errtype"
)

// GRPCStatusCodeString returns the canonical gRPC status code string per semconv.
// It returns "" when status is not a valid gRPC code (0-16) — e.g. an HTTP
// status that leaked through protocol detection, or a failed eBPF status read.
// Callers must then omit the attribute instead of emitting a made-up value
// that would violate the semconv gRPC status enum.
func GRPCStatusCodeString(status int) string {
	return errtype.GRPCCode(status)
}
