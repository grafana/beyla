// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

func extractSymfonyLegacyRoutes(file phpFile, projectRoot string, supportsFOSRest bool, routes routeSet) {
	extractSymfonyLegacyAnnotations(file.tokens, supportsFOSRest, routes)
	extractSymfonyLegacyPHP(file.path, projectRoot, file.tokens, routes)
}

func extractSymfonyLegacyConfigRoutes(projectRoot string, routes routeSet) {
	yamlTraversal := newSymfonyConfigTraversal()
	for _, entry := range legacySymfonyYAMLEntries(projectRoot) {
		extractSymfonyYAMLFile(projectRoot, entry, "", yamlTraversal, nil, nil, routes)
	}

	xmlTraversal := newSymfonyConfigTraversal()
	for _, entry := range legacySymfonyXMLEntries(projectRoot) {
		extractSymfonyXMLFile(projectRoot, entry, "", xmlTraversal, nil, nil, routes)
	}
}
