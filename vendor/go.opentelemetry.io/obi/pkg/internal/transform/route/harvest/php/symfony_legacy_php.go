// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"path/filepath"
	"strings"
)

// extractSymfonyLegacyPHP reads static new Route(...) calls from legacy Symfony PHP route configuration files.
// For example, app/config/routing.php containing a Symfony Route import and new Route("/users") adds /users.
func extractSymfonyLegacyPHP(filePath, projectRoot string, tokens []token, routes routeSet) {
	if !isLegacySymfonyConfig(filePath, projectRoot) || !importsSymfonyRoute(tokens) {
		return
	}

	for pos := 0; pos+2 < len(tokens); pos++ {
		if !equalName(tokens[pos], "new") {
			continue
		}

		className := tokens[pos+1]
		if className.kind != tokenName || !strings.EqualFold(shortPHPName(className.value), "Route") {
			continue
		}

		openingParenthesis := pos + 2
		if tokens[openingParenthesis].value != "(" {
			continue
		}

		if path, ok := staticStringArgument(callArguments(tokens, openingParenthesis), 0); ok {
			routes.add(path)
		}
	}
}

func importsSymfonyRoute(tokens []token) bool {
	for pos := 0; pos+1 < len(tokens); pos++ {
		if equalName(tokens[pos], "use") &&
			strings.EqualFold(strings.TrimPrefix(tokens[pos+1].value, "\\"), "Symfony\\Component\\Routing\\Route") {
			return true
		}
	}

	return false
}

func isLegacySymfonyConfig(filePath, projectRoot string) bool {
	relativePath, err := filepath.Rel(projectRoot, filePath)
	if err != nil {
		return false
	}

	relativePath = filepath.ToSlash(relativePath)
	return strings.HasPrefix(relativePath, "app/config/") || strings.HasPrefix(relativePath, "config/routes/")
}
