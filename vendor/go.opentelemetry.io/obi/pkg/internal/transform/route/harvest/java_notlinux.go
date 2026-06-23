// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type JavaRoutes struct{}

func NewJavaRoutesHarvester() *JavaRoutes {
	return &JavaRoutes{}
}

func (h *JavaRoutes) ExtractRoutes(_ context.Context, _ *exec.FileInfo) (*RouteHarvesterResult, error) {
	return nil, nil
}
