// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import "regexp"

var fastAPIPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^@` + pyObj + `(?:get|post|put|patch|delete|head|options|trace|api_route)\s*\(\s*` + pyLit),
	regexp.MustCompile(`^@` + pyObj + `(?:get|post|put|patch|delete|head|options|trace|api_route)\s*\([^)]*\bpath\s*=\s*` + pyLit),
	regexp.MustCompile(`\b` + pyObj + `add_api_route\s*\(\s*` + pyLit),
	regexp.MustCompile(`\b` + pyObj + `add_api_route\s*\([^)]*\bpath\s*=\s*` + pyLit),
	regexp.MustCompile(`\b(?:` + pyObj + `)?APIRouter\s*\([^)]*\bprefix\s*=\s*` + pyLit),
	regexp.MustCompile(`\b` + pyObj + `include_router\s*\([^)]*\bprefix\s*=\s*` + pyLit),
}

var fastAPIStart = regexp.MustCompile(
	`(?:^@` + pyObj + `(?:get|post|put|patch|delete|head|options|trace|api_route)|\b` +
		pyObj + `(?:add_api_route|include_router)|\b(?:` + pyObj + `)?APIRouter)\s*\(`,
)

func scanFastAPI(line string, routes map[string]struct{}) {
	for _, re := range fastAPIPatterns {
		addPyMatch(routes, re, line)
	}
}

func startsFastAPI(line string) bool {
	return fastAPIStart.MatchString(line)
}
