// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

// Symfony config parsing starts at config/routes.{yaml,yml,xml}, and YAML or XML files under config/routes.
// Local imports are followed recursively with their prefixes, while attribute imports reuse routes harvested
// from PHP files. symfonyConfigTraversal prevents import cycles while allowing a file under multiple prefixes.
//
// extractSymfonyConfigRoutes
//
//	 -> symfonyConfigEntries
//	    -> extractSymfonyConfigFile
//	       -> extractSymfonyYAMLFile
//	          -> extractSymfonyYAMLMapping
//	             -> direct path routes
//	             -> local YAML/XML imports: extractSymfonyConfigFile
//	             -> attribute imports: addImportedSymfonyAttributes
//	       -> extractSymfonyXMLFile
//	          -> direct path routes
//	          -> extractSymfonyXMLImport
//	             -> local YAML/XML imports: extractSymfonyConfigFile
//	             -> attribute imports: addImportedSymfonyAttributes
//
//	Both file parsers use symfonyConfigTraversal to stop cycles while allowing a file under multiple prefixes.
func extractSymfonyConfigRoutes(projectRoot string, attributes map[string][]string, routes routeSet) map[string]struct{} {
	traversal := newSymfonyConfigTraversal()
	imported := map[string]struct{}{}

	for _, entry := range symfonyConfigEntries(projectRoot) {
		extractSymfonyConfigFile(projectRoot, entry, "", traversal, attributes, imported, routes)
	}

	return imported
}

func extractSymfonyConfigFile(
	projectRoot, filePath, routePrefix string,
	traversal *symfonyConfigTraversal,
	attributes map[string][]string,
	imported map[string]struct{},
	routes routeSet,
) {
	switch {
	case isYAMLFile(filePath):
		extractSymfonyYAMLFile(projectRoot, filePath, routePrefix, traversal, attributes, imported, routes)
	case isXMLFile(filePath):
		extractSymfonyXMLFile(projectRoot, filePath, routePrefix, traversal, attributes, imported, routes)
	}
}
