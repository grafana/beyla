// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import "strings"

var apiPlatformAttributes = map[string]struct{}{
	"apiresource":      {},
	"delete":           {},
	"get":              {},
	"getcollection":    {},
	"graphqloperation": {},
	"patch":            {},
	"post":             {},
	"put":              {},
}

// extractAPIPlatformRoutes reads static uriTemplate values from API Platform attributes, for example:
//
//	#[ApiResource(operations: [new Get(uriTemplate: '/books/{id}')])]
//
// adds /books/{id}.
func extractAPIPlatformRoutes(tokens []token, routes routeSet) {
	for pos := 0; pos < len(tokens); pos++ {
		if tokens[pos].value != "#[" {
			continue
		}

		closingBracket := matchingAttributeEnd(tokens, pos)
		if closingBracket < 0 {
			continue
		}

		for _, attribute := range splitOnTopLevelCommas(tokens[pos+1 : closingBracket]) {
			if isAPIPlatformAttribute(attribute) {
				addAPIPlatformURITemplates(attribute, routes)
			}
		}

		pos = closingBracket
	}
}

func isAPIPlatformAttribute(tokens []token) bool {
	if len(tokens) == 0 || tokens[0].kind != tokenName {
		return false
	}

	_, ok := apiPlatformAttributes[strings.ToLower(shortPHPName(tokens[0].value))]
	return ok
}

func addAPIPlatformURITemplates(tokens []token, routes routeSet) {
	for pos := 0; pos+2 < len(tokens); pos++ {
		if tokens[pos].kind != tokenName || !strings.EqualFold(tokens[pos].value, "uriTemplate") {
			continue
		}

		if tokens[pos+1].value == ":" && tokens[pos+2].kind == tokenString {
			routes.add(tokens[pos+2].value)
		}
	}
}
