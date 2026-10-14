// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"bytes"
	"encoding/xml"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

func extractSymfonyXMLFile(
	projectRoot, filePath, routePrefix string,
	traversal *symfonyConfigTraversal,
	attributes map[string][]string,
	imported map[string]struct{},
	routes routeSet,
) {
	if !traversal.enter(filePath, routePrefix) {
		return
	}
	defer traversal.leave(filePath)

	data, _, err := langtools.ReadMetadataFile(filePath, maxPHPFileBytes)
	if err != nil || data == nil {
		return
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		xmlToken, err := decoder.Token()
		if err != nil {
			return
		}

		startElement, ok := xmlToken.(xml.StartElement)
		if !ok {
			continue
		}

		switch startElement.Name.Local {
		case "route":
			if routePath := symfonyXMLPath(startElement); routePath != "" {
				routes.add(joinRoutes(routePrefix, routePath))
			}
		case "import":
			extractSymfonyXMLImport(
				projectRoot,
				filepath.Dir(filePath),
				routePrefix,
				startElement,
				traversal,
				attributes,
				imported,
				routes,
			)
		}
	}
}

func symfonyXMLPath(startElement xml.StartElement) string {
	if path := xmlAttribute(startElement, "path"); path != "" {
		return path
	}

	// Symfony used pattern as the route path field before introducing path.
	return xmlAttribute(startElement, "pattern")
}

func extractSymfonyXMLImport(
	projectRoot, baseDirectory, routePrefix string,
	startElement xml.StartElement,
	traversal *symfonyConfigTraversal,
	attributes map[string][]string,
	imported map[string]struct{},
	routes routeSet,
) {
	resource, ok := localSymfonyResource(projectRoot, baseDirectory, xmlAttribute(startElement, "resource"))
	if !ok {
		return
	}

	importPrefix := joinRoutes(routePrefix, xmlAttribute(startElement, "prefix"))
	if isSymfonyXMLAttributeImport(startElement) {
		addImportedSymfonyAttributes(resource, importPrefix, attributes, imported, routes)
		return
	}

	extractSymfonyConfigFile(projectRoot, resource, importPrefix, traversal, attributes, imported, routes)
}

func isSymfonyXMLAttributeImport(startElement xml.StartElement) bool {
	typeName := strings.ToLower(xmlAttribute(startElement, "type"))
	return typeName == "attribute" || typeName == "annotation"
}

func xmlAttribute(startElement xml.StartElement, name string) string {
	for _, attribute := range startElement.Attr {
		if attribute.Name.Local == name {
			return attribute.Value
		}
	}

	return ""
}
