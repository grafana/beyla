// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package errtype owns the error.type values OBI emits, so the span pipeline and
// the internal-metrics exporters cannot spell the same condition two ways.
package errtype // import "go.opentelemetry.io/obi/pkg/internal/errtype"

import (
	grpc_codes "google.golang.org/grpc/codes"
)

// Other is the semantic-convention value for an error whose type cannot be determined.
const Other = "_OTHER"

// GRPCCode returns the canonical gRPC status code string per semconv.
// It returns "" when status is not a valid gRPC code (0-16) — e.g. an HTTP
// status that leaked through protocol detection, or a failed eBPF status read.
// Callers must then omit the attribute instead of emitting a made-up value
// that would violate the semconv gRPC status enum.
func GRPCCode(status int) string {
	switch grpc_codes.Code(status) {
	case grpc_codes.OK:
		return "OK"
	case grpc_codes.Canceled:
		return "CANCELLED"
	case grpc_codes.Unknown:
		return "UNKNOWN"
	case grpc_codes.InvalidArgument:
		return "INVALID_ARGUMENT"
	case grpc_codes.DeadlineExceeded:
		return "DEADLINE_EXCEEDED"
	case grpc_codes.NotFound:
		return "NOT_FOUND"
	case grpc_codes.AlreadyExists:
		return "ALREADY_EXISTS"
	case grpc_codes.PermissionDenied:
		return "PERMISSION_DENIED"
	case grpc_codes.ResourceExhausted:
		return "RESOURCE_EXHAUSTED"
	case grpc_codes.FailedPrecondition:
		return "FAILED_PRECONDITION"
	case grpc_codes.Aborted:
		return "ABORTED"
	case grpc_codes.OutOfRange:
		return "OUT_OF_RANGE"
	case grpc_codes.Unimplemented:
		return "UNIMPLEMENTED"
	case grpc_codes.Internal:
		return "INTERNAL"
	case grpc_codes.Unavailable:
		return "UNAVAILABLE"
	case grpc_codes.DataLoss:
		return "DATA_LOSS"
	case grpc_codes.Unauthenticated:
		return "UNAUTHENTICATED"
	default:
		return ""
	}
}
