// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

type resolverAnalysisCache struct{}

func newResolverAnalysisCache() resolverAnalysisCache { return resolverAnalysisCache{} }

// Resolve reports CPython runtime collection as unsupported off Linux.
func (*Resolver) Resolve(context.Context, app.PID, uint64) (*MetricTarget, error) {
	return nil, errUnsupportedLayout
}

// ProcessStartTime reports process lifecycle lookup as unsupported off Linux.
func ProcessStartTime(app.PID) (uint64, error) { return 0, errUnsupportedLayout }
