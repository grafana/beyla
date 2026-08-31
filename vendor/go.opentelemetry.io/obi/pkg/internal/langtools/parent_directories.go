// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package langtools // import "go.opentelemetry.io/obi/pkg/internal/langtools"

import "path/filepath"

// WalkParentDirectories visits start and each parent through boundary, inclusive.
// Traversal ends when visit returns stop as true.
func WalkParentDirectories(start, boundary string, visit func(string) (stop bool, err error)) error {
	if !filepath.IsAbs(start) || !filepath.IsAbs(boundary) {
		return nil
	}

	dir := filepath.Clean(start)
	boundary = filepath.Clean(boundary)
	if !pathInRoot(boundary, dir) {
		return nil
	}

	for {
		stop, err := visit(dir)
		if err != nil || stop {
			return err
		}
		if dir == boundary {
			return nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}
