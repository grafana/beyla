// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	javaharvest "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/java"
)

type JavaRoutes struct {
	log *slog.Logger
}

func NewJavaRoutesHarvester() *JavaRoutes {
	return &JavaRoutes{
		log: slog.With("component", "route.harvester.java"),
	}
}

func (h *JavaRoutes) ExtractRoutes(fileInfo *exec.FileInfo) (*RouteHarvesterResult, error) {
	routes, err := javaharvest.ExtractRoutes(fileInfo)
	if err != nil {
		return nil, fmt.Errorf("extracting Java routes from class files: %w", err)
	}

	h.log.Debug("java routes", "routes", routes)

	return &RouteHarvesterResult{Routes: routes, Kind: PartialRoutes}, nil
}
