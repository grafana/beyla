// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/phptools"
	phpharvest "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"
)

func ExtractPHPRoutes(ctx context.Context, fileInfo *exec.FileInfo) (*RouteHarvesterResult, error) {
	project, err := phptools.ProjectForPID(fileInfo)
	if project.Root == "" {
		return nil, err
	}

	routes, err := phpharvest.ExtractRoutes(ctx, project.Root)
	if err != nil || routes == nil {
		return nil, err
	}

	return &RouteHarvesterResult{Routes: routes, Kind: PartialRoutes}, nil
}
