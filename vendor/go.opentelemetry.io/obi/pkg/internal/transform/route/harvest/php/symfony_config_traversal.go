// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

type symfonyConfigTraversal struct {
	visited map[symfonyConfigVisit]struct{}
	active  map[string]struct{}
}

type symfonyConfigVisit struct {
	filePath    string
	routePrefix string
}

func newSymfonyConfigTraversal() *symfonyConfigTraversal {
	return &symfonyConfigTraversal{
		visited: map[symfonyConfigVisit]struct{}{},
		active:  map[string]struct{}{},
	}
}

func (traversal *symfonyConfigTraversal) enter(filePath, routePrefix string) bool {
	visit := symfonyConfigVisit{filePath: filePath, routePrefix: routePrefix}
	if _, visited := traversal.visited[visit]; visited {
		return false
	}

	if _, active := traversal.active[filePath]; active {
		return false
	}

	// A file may be imported under several prefixes, but an active file always indicates an import cycle.
	traversal.visited[visit] = struct{}{}
	traversal.active[filePath] = struct{}{}
	return true
}

func (traversal *symfonyConfigTraversal) leave(filePath string) {
	delete(traversal.active, filePath)
}
