// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics // import "go.opentelemetry.io/obi/pkg/export/imetrics"

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/obi/pkg/internal/errtype"
)

// ExportErrorType classifies an export failure into a low-cardinality error.type value.
// The error message is unsuitable as an attribute: it embeds endpoints and deadlines, so
// it mints a new series per distinct failure.
//
// Each check uses errors.Is or errors.As, so it sees through the wrapping the OTLP
// exporters add. A failure matching none of them is reported as _OTHER rather than by Go
// type, because the type of an unrecognized error names the wrapper that carried it.
func ExportErrorType(err error) string {
	if err == nil {
		return errtype.Other
	}

	if st, ok := status.FromError(err); ok && st.Code() != codes.OK {
		if code := errtype.GRPCCode(int(st.Code())); code != "" {
			return code
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return errtype.GRPCCode(int(codes.DeadlineExceeded))
	}
	if errors.Is(err, context.Canceled) {
		return errtype.GRPCCode(int(codes.Canceled))
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return errtype.GRPCCode(int(codes.DeadlineExceeded))
		}

		return fmt.Sprintf("%T", netErr)
	}

	return errtype.Other
}
