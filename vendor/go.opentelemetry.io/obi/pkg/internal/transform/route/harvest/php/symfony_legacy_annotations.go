// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import "regexp"

var (
	legacyRouteAnnotation = regexp.MustCompile(`(?i)@(?:[A-Za-z_][A-Za-z0-9_\\]*\\)?Route\s*\(\s*(?:path\s*=\s*)?["']([^"']+)["']`)
	// Matches path= when it is not the annotation's first argument, e.g. @Route(name="x", path="/y").
	legacyRouteAnnotationNamedPath = regexp.MustCompile(`(?i)@(?:[A-Za-z_][A-Za-z0-9_\\]*\\)?Route\s*\([^)]*,[^)]*?\bpath\s*=\s*["']([^"']+)["']`)
	// FOS = FriendsOfSymfony
	legacyFOSRestAnnotation          = regexp.MustCompile(`(?i)@(?:Rest\\)?(?:Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*(?:path\s*=\s*)?["']([^"']+)["']`)
	legacyFOSRestAnnotationNamedPath = regexp.MustCompile(`(?i)@(?:Rest\\)?(?:Get|Post|Put|Patch|Delete|Head|Options)\s*\([^)]*,[^)]*?\bpath\s*=\s*["']([^"']+)["']`)
)

// extractSymfonyLegacyAnnotations associates route annotations in doc comments with the class or function.
// A class @Route("/api") and method @Route("/users") produce /api/users.
// supportsFOSRest also enables @Rest\Get and similar annotations.
func extractSymfonyLegacyAnnotations(tokens []token, supportsFOSRest bool, routes routeSet) {
	var pendingPaths []string
	for pos := 0; pos < len(tokens); pos++ {
		if tokens[pos].kind == tokenDocComment {
			pendingPaths = legacyAnnotationPaths(tokens[pos].value, supportsFOSRest)
			continue
		}

		if isPHPDeclaration(tokens, pos, "class") {
			openingBrace := nextTokenValueIndex(tokens, pos+1, "{")
			if closingBrace := matchingClosingToken(tokens, openingBrace, "{", "}"); closingBrace >= 0 {
				extractSymfonyLegacyMethods(tokens, openingBrace+1, closingBrace, pendingPaths, supportsFOSRest, routes)
				pos = closingBrace
			}

			pendingPaths = nil
			continue
		}

		if equalName(tokens[pos], "function") {
			addSymfonyPaths(routes, nil, pendingPaths)
			pendingPaths = nil
		}
	}
}

func extractSymfonyLegacyMethods(
	tokens []token,
	startIndex, endIndex int,
	classPaths []string,
	supportsFOSRest bool,
	routes routeSet,
) {
	braceDepth := 0
	var pendingPaths []string
	for pos := startIndex; pos < endIndex; pos++ {
		if tokens[pos].kind == tokenSymbol {
			switch tokens[pos].value {
			case "{":
				braceDepth++
				continue
			case "}":
				braceDepth--
				continue
			}
		}

		if braceDepth != 0 {
			continue
		}

		if tokens[pos].kind == tokenDocComment {
			pendingPaths = legacyAnnotationPaths(tokens[pos].value, supportsFOSRest)
			continue
		}

		if equalName(tokens[pos], "function") {
			addSymfonyPaths(routes, classPaths, pendingPaths)
			pendingPaths = nil
		}
	}
}

func legacyAnnotationPaths(comment string, supportsFOSRest bool) []string {
	paths := annotationMatches(legacyRouteAnnotation, comment)
	paths = append(paths, annotationMatches(legacyRouteAnnotationNamedPath, comment)...)

	if supportsFOSRest {
		paths = append(paths, annotationMatches(legacyFOSRestAnnotation, comment)...)
		paths = append(paths, annotationMatches(legacyFOSRestAnnotationNamedPath, comment)...)
	}

	return paths
}

func annotationMatches(pattern *regexp.Regexp, comment string) []string {
	matches := pattern.FindAllStringSubmatch(comment, -1)
	paths := make([]string, 0, len(matches))

	for _, match := range matches {
		if len(match) == 2 {
			paths = append(paths, match[1])
		}
	}

	return paths
}
