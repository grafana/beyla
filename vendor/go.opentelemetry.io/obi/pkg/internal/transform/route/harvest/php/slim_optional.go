// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import "strings"

func expandSlimOptionalSegments(route string) []string {
	stripped, variantEnds, ok := stripSlimOptionalSegments(route)
	if !ok || len(variantEnds) == 0 {
		return []string{route}
	}

	variants := make([]string, 0, len(variantEnds)+1)
	for _, end := range variantEnds {
		variants = append(variants, stripped[:end])
	}

	return append(variants, stripped)
}

func stripSlimOptionalSegments(route string) (string, []int, bool) {
	if !strings.Contains(route, "[") {
		return route, nil, true
	}

	var stripped strings.Builder
	var variantEnds []int
	braceDepth := 0
	optionalDepth := 0

	for pos := range len(route) {
		char := route[pos]

		// Brackets inside a placeholder belong to its regular expression.
		switch {
		case char == '{':
			braceDepth++
		case char == '}' && braceDepth > 0:
			braceDepth--
		case braceDepth == 0 && char == '[':
			variantEnds = append(variantEnds, stripped.Len())
			optionalDepth++
			continue
		case braceDepth == 0 && char == ']' && optionalDepth > 0:
			optionalDepth--
			if optionalDepth == 0 && pos != len(route)-1 {
				return route, nil, false
			}
			continue
		}

		stripped.WriteByte(char)
	}

	if optionalDepth != 0 {
		return route, nil, false
	}

	return stripped.String(), variantEnds, true
}
