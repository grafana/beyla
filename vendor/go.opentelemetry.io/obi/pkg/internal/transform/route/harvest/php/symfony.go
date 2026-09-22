// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import "strings"

func extractSymfonyRoutes(tokens []token, routes routeSet) []string {
	attributes := newRouteSet()
	extractSymfonyAttributes(tokens, attributes)
	extractSymfonyPHPConfig(tokens, routes)
	return attributes.sorted()
}

// extractSymfonyAttributes finds Symfony #[Route] attributes and combines the class level prefixes with method level paths, for
// example:
// #[Route('/api')]
// class UserController
//
//	{
//	    #[Route('/users')]
//	    public function list(): Response {}
//
//	    #[Route(path: '/users/{id}')]
//	    public function show(int $id): Response {}
//	}
//
// #[Route('/health')]
// function health(): Response {}
//
// gets us
//
// /api/users
// /api/users/{id}
// /health
func extractSymfonyAttributes(tokens []token, routes routeSet) {
	var pendingPaths []string
	for pos := 0; pos < len(tokens); pos++ {
		if tokens[pos].value == "#[" {
			paths, closingBracket := symfonyAttributePaths(tokens, pos)
			pendingPaths = append(pendingPaths, paths...)
			pos = closingBracket
			continue
		}

		if isPHPDeclaration(tokens, pos, "class") {
			openingBrace := nextTokenValueIndex(tokens, pos+1, "{")
			if closingBrace := matchingClosingToken(tokens, openingBrace, "{", "}"); closingBrace >= 0 {
				extractSymfonyMethods(tokens, openingBrace+1, closingBrace, pendingPaths, routes)
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

func isPHPDeclaration(tokens []token, position int, name string) bool {
	if !equalName(tokens[position], name) {
		return false
	}

	// Example::class is a constant access, not a class declaration, make sure we can tell them apart
	return position == 0 || tokens[position-1].value != "::"
}

func extractSymfonyMethods(tokens []token, startIndex, endIndex int, classPaths []string, routes routeSet) {
	braceDepth := 0
	var pendingPaths []string
	for pos := startIndex; pos < endIndex; pos++ {
		if tokens[pos].kind == tokenSymbol && tokens[pos].value == "{" {
			braceDepth++
			continue
		}

		if tokens[pos].kind == tokenSymbol && tokens[pos].value == "}" {
			braceDepth--
			continue
		}

		if braceDepth != 0 {
			continue
		}

		if tokens[pos].value == "#[" {
			paths, closingBracket := symfonyAttributePaths(tokens, pos)
			pendingPaths = append(pendingPaths, paths...)
			pos = closingBracket
			continue
		}

		if equalName(tokens[pos], "function") {
			addSymfonyPaths(routes, classPaths, pendingPaths)
			pendingPaths = nil
		}
	}
}

func symfonyAttributePaths(tokens []token, startIndex int) ([]string, int) {
	closingBracket := matchingAttributeEnd(tokens, startIndex)
	if closingBracket < 0 {
		return nil, startIndex
	}

	var paths []string
	for _, attribute := range splitOnTopLevelCommas(tokens[startIndex+1 : closingBracket]) {
		if path, ok := symfonyRouteAttributePath(attribute); ok {
			paths = append(paths, path)
		}
	}

	return paths, closingBracket
}

func matchingAttributeEnd(tokens []token, startIndex int) int {
	if startIndex < 0 || startIndex >= len(tokens) || tokens[startIndex].kind != tokenSymbol || tokens[startIndex].value != "#[" {
		return -1
	}

	bracketDepth := 0
	for pos := startIndex; pos < len(tokens); pos++ {
		if tokens[pos].kind != tokenSymbol {
			continue
		}

		switch tokens[pos].value {
		case "#[", "[":
			bracketDepth++
		case "]":
			bracketDepth--
			if bracketDepth == 0 {
				return pos
			}
		}
	}

	return -1
}

func symfonyRouteAttributePath(attribute []token) (string, bool) {
	if len(attribute) < 3 || attribute[0].kind != tokenName || !strings.EqualFold(shortPHPName(attribute[0].value), "Route") {
		return "", false
	}

	if attribute[1].value != "(" {
		return "", false
	}

	arguments := callArguments(attribute, 1)
	if path, ok := staticStringArgument(arguments, 0); ok {
		return path, true
	}

	return namedLiteralArgument(arguments, "path")
}

func addSymfonyPaths(routes routeSet, classPaths, methodPaths []string) {
	if len(classPaths) == 0 {
		for _, path := range methodPaths {
			routes.add(path)
		}
		return
	}

	for _, classPath := range classPaths {
		for _, methodPath := range methodPaths {
			routes.add(joinRoutes(classPath, methodPath))
		}
	}
}

func shortPHPName(name string) string {
	name = strings.Trim(name, "\\")
	if index := strings.LastIndexByte(name, '\\'); index >= 0 {
		return name[index+1:]
	}

	return name
}

func nextTokenValueIndex(tokens []token, startIndex int, value string) int {
	if startIndex < 0 {
		return -1
	}

	for pos := startIndex; pos < len(tokens); pos++ {
		if tokens[pos].value == value {
			return pos
		}
	}

	return -1
}
