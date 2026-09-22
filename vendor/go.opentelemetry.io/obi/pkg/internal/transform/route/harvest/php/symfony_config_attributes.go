// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"path/filepath"
	"strings"
)

func addImportedSymfonyAttributes(
	resourcePath, routePrefix string,
	attributes map[string][]string,
	imported map[string]struct{},
	routes routeSet,
) {
	for sourcePath, attributePaths := range attributes {
		if !isPathWithinResource(sourcePath, resourcePath) {
			continue
		}

		imported[sourcePath] = struct{}{}
		for _, routePath := range attributePaths {
			routes.add(joinRoutes(routePrefix, routePath))
		}
	}
}

func isPathWithinResource(path, resourcePath string) bool {
	if path == resourcePath {
		return true
	}

	resourceDirectory := strings.TrimRight(resourcePath, string(filepath.Separator)) + string(filepath.Separator)
	return strings.HasPrefix(path, resourceDirectory)
}
