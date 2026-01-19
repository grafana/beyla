// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package route // import "go.opentelemetry.io/obi/pkg/internal/transform/route"

import (
	"regexp"
	"strings"
)

// PartialRouteMatcher allows matching a given URL path towards a set of framework-like provided
// patterns.
type PartialRouteMatcher struct {
	roots           []*node
	hasAbsoluteRoot bool
}

// NewPartialRouteMatcher creates a new Matcher that would allow validating given URL paths towards
// the provided set of routes
func NewPartialRouteMatcher(routes []string) *PartialRouteMatcher {
	m := PartialRouteMatcher{roots: []*node{}}

	// Deduplicate single parameter routes of type /{something}
	routes = deduplicateSingleParamRoutes(routes)

	for _, route := range routes {
		if route == "/" {
			m.hasAbsoluteRoot = true
			continue
		}
		n := &node{Child: map[string]*node{}}
		m.roots = append(m.roots, n)
		appendRoute(route, tokenize(route), n)
	}
	return &m
}

// Find the router pattern that would match a given URL path, or empty if no pattern
// matches it. Uses partial matching across multiple root trees.
func (rm *PartialRouteMatcher) Find(path string) string {
	if path == "/" && rm.hasAbsoluteRoot {
		return path
	}

	tokens := tokenize(path)
	return rm.findCombined(tokens, 0, make([]string, len(tokens)), 0)
}

// findCombined tries to match the full path using combinations of partial matches from different roots
func (rm *PartialRouteMatcher) findCombined(tokens []string, startIdx int, matchedParts []string, matchedLen int) string {
	// If we've consumed all tokens, we found a complete match
	if startIdx >= len(tokens) {
		if matchedLen > 0 {
			return strings.Join(matchedParts[:matchedLen], "")
		}
		return ""
	}

	newMatchedParts := matchedParts

	// This check is here for ensuring that we don't run into unexpected condition where
	// the original tokens slice is shorter than the parts slice. In practice, this should
	// never happen, the tokens will always be >= to the number of parts. However, if we
	// encounter unexpected pattern and we don't expand the array we'll hit a panic.
	if matchedLen == len(matchedParts) {
		newMatchedParts = make([]string, len(matchedParts)+1)
		copy(newMatchedParts, matchedParts)
	}

	// Try each root tree for partial matching from current position
	for _, root := range rm.roots {
		if partialMatch, consumed := rm.findPartial(tokens[startIdx:], root); partialMatch != "" && consumed > 0 {
			// Found a partial match, try to match the rest
			newMatchedParts[matchedLen] = partialMatch

			if result := rm.findCombined(tokens, startIdx+consumed, newMatchedParts, matchedLen+1); result != "" {
				return result
			}
		}
	}

	return ""
}

// findPartial attempts to match as many tokens as possible from a single root, returns the matched route and tokens consumed
func (rm *PartialRouteMatcher) findPartial(tokens []string, root *node) (string, int) {
	return rm.findPartialRecursive(tokens, root, 0)
}

func (rm *PartialRouteMatcher) findPartialRecursive(tokens []string, node *node, consumed int) (string, int) {
	// If we have a valid route at this point, it's a potential partial match
	if node.FullRoute != "" {
		// Return this match and how many tokens we consumed
		return node.FullRoute, consumed
	}

	// If no more tokens to consume, return empty
	if consumed >= len(tokens) {
		return "", 0
	}

	currentToken := tokens[consumed]

	// Try exact match first
	if child, ok := node.Child[currentToken]; ok {
		return rm.findPartialRecursive(tokens, child, consumed+1)
	}

	// Try wildcard match
	if node.Wildcard != nil {
		return rm.findPartialRecursive(tokens, node.Wildcard, consumed+1)
	}

	// No match found
	return "", 0
}

// deduplicateSingleParamRoutes processes routes to find patterns of type /{something}
// (routes with single parameter prefixed with /) and if there are multiple such patterns,
// removes them all and replaces with /{id}
func deduplicateSingleParamRoutes(routes []string) []string {
	singleParamPattern := regexp.MustCompile(`^/\{[^/}]+\}$`)
	var singleParamRoutes []string
	var otherRoutes []string

	// Separate single parameter routes from others
	for _, route := range routes {
		if singleParamPattern.MatchString(route) {
			singleParamRoutes = append(singleParamRoutes, route)
		} else {
			otherRoutes = append(otherRoutes, route)
		}
	}

	// If we have more than one single parameter route, replace them all with /{id}
	if len(singleParamRoutes) > 1 {
		otherRoutes = append(otherRoutes, "/{id}")
	} else if len(singleParamRoutes) == 1 {
		// Keep the single one as is
		otherRoutes = append(otherRoutes, singleParamRoutes[0])
	}

	return otherRoutes
}
