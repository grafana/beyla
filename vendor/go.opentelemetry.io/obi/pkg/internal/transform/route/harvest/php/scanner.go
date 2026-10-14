// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxPHPFileBytes int64 = 10 * 1024 * 1024
	maxPHPFiles           = 10_000
)

var skippedDirectories = map[string]struct{}{
	".git":            {},
	".hg":             {},
	".svn":            {},
	"bootstrap/cache": {},
	"examples":        {},
	"fixtures":        {},
	"node_modules":    {},
	"spec":            {},
	"specs":           {},
	"storage":         {},
	"test":            {},
	"tests":           {},
	"var/cache":       {},
	"vendor":          {},
}

type phpFile struct {
	path   string
	tokens []token
}

func walkPHPFiles(ctx context.Context, root string, visit func(phpFile)) error {
	filesRead := 0
	processEntry := func(path string, entry fs.DirEntry, pathErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if pathErr != nil {
			// a root error prevents the scan
			// errors below it only skip the unreadable entry
			if path == root {
				return pathErr
			}

			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		if entry.IsDir() {
			if path != root && shouldSkipDirectory(root, path) {
				return filepath.SkipDir
			}

			return nil
		}

		if filesRead >= maxPHPFiles {
			return filepath.SkipAll
		}

		if !isRegularPHPFile(path, entry) {
			return nil
		}

		data, _, err := langtools.ReadMetadataFile(path, maxPHPFileBytes)
		if err != nil || data == nil {
			return nil
		}

		tokens := lexPHP(data)
		filesRead++
		visit(phpFile{path: path, tokens: tokens})

		return nil
	}

	err := filepath.WalkDir(root, processEntry)
	if err != nil {
		return fmt.Errorf("scan PHP project: %w", err)
	}

	return nil
}

func isRegularPHPFile(path string, entry fs.DirEntry) bool {
	return entry.Type().IsRegular() && strings.EqualFold(filepath.Ext(path), ".php")
}

func shouldSkipDirectory(root, path string) bool {
	relativePath, err := filepath.Rel(root, path)
	if err != nil {
		return true
	}

	relativePath = filepath.ToSlash(relativePath)
	// multi part entries are root-relative
	// single directory names apply at any depth
	if _, skip := skippedDirectories[relativePath]; skip {
		return true
	}

	_, skip := skippedDirectories[filepath.Base(relativePath)]
	return skip
}
