// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"sort"
	"strings"
)

const (
	maxRoutes = 10_000
	// Covers {name}, :name, [optional], and *wildcard forms used by the supported frameworks.
	dynamicRouteSegmentMarkers = "{[:*"
)

type routeSet map[string]struct{}

func newRouteSet() routeSet {
	return make(routeSet)
}

func (routes routeSet) add(value string) {
	if len(routes) >= maxRoutes {
		return
	}

	if route := normalizeRoute(value); route != "" {
		routes[route] = struct{}{}
	}
}

func (routes routeSet) sorted() []string {
	sortedRoutes := make([]string, 0, len(routes))

	for route := range routes {
		sortedRoutes = append(sortedRoutes, route)
	}

	// prefer more static segments, then longer routes, with lexical order as tie breaker
	sort.Slice(sortedRoutes, func(i, j int) bool {
		leftRoute := sortedRoutes[i]
		rightRoute := sortedRoutes[j]
		leftPriority := routeSortPriority(leftRoute)
		rightPriority := routeSortPriority(rightRoute)

		if leftPriority != rightPriority {
			return leftPriority > rightPriority
		}

		if len(leftRoute) != len(rightRoute) {
			return len(leftRoute) > len(rightRoute)
		}

		return leftRoute < rightRoute
	})

	return sortedRoutes
}

func normalizeRoute(route string) string {
	route = strings.TrimSpace(route)
	if route == "" {
		return ""
	}

	route = "/" + strings.TrimLeft(route, "/")
	if route != "/" {
		route = strings.TrimRight(route, "/")
	}

	return route
}

func joinRoutes(parts ...string) string {
	var route strings.Builder
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part == "" {
			continue
		}

		route.WriteByte('/')
		route.WriteString(part)
	}

	if route.Len() == 0 {
		return "/"
	}

	return route.String()
}

func routeSortPriority(route string) int {
	staticSegmentCount := 0

	for segment := range strings.SplitSeq(strings.Trim(route, "/"), "/") {
		if segment == "" {
			continue
		}

		if strings.ContainsAny(segment, dynamicRouteSegmentMarkers) {
			continue
		}

		staticSegmentCount++
	}

	return staticSegmentCount
}
