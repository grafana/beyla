// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import "strings"

func slimRouteVariants(route string) []string {
	variants := expandSlimOptionalSegments(route)
	for pos := range variants {
		variants[pos] = normalizeSlimPattern(variants[pos])
	}
	return variants
}

func normalizeSlimPattern(pattern string) string {
	segments := strings.Split(pattern, "/")
	for pos, segment := range segments {
		if !strings.HasPrefix(segment, "{") || !strings.HasSuffix(segment, "}") {
			continue
		}

		placeholder := segment[1 : len(segment)-1]
		name, constraint, found := strings.Cut(placeholder, ":")
		if !found || name == "" || constraint == "" {
			continue
		}

		if constraint == ".*" {
			segments[pos] = "{*" + name + "}"
		} else {
			segments[pos] = "{" + name + "}"
		}
	}

	return strings.Join(segments, "/")
}
