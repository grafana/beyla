// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

var (
	railsMount        = regexp.MustCompile(`^mount\s*\(?\s*(?:::)?([A-Z][A-Za-z_0-9]*(?:::[A-Z][A-Za-z_0-9]*)*)\s*(?:=>|,\s*(?:at:|:at\s*=>))\s*(.*)$`)
	railsEngineRoutes = regexp.MustCompile(`^(?:::)?([A-Z][A-Za-z_0-9]*(?:::[A-Z][A-Za-z_0-9]*)*)\.routes\.draw\s+do\s*$`)
)

func railsMountValue(line string) (string, string, bool) {
	match := railsMount.FindStringSubmatch(line)
	if match == nil {
		return "", "", false
	}
	path, ok := railsLiteralValue(match[2])
	if !ok || path == "" || strings.ContainsAny(path, "()*") {
		return "", "", false
	}
	return match[1], path, true
}

// Index conventional local engines by their routes.draw receiver, not their
// directory name: component names need not match Ruby constants. Only mounted
// engines are subsequently harvested; installed gems and dynamic mounts are not resolved.
func findRailsEngines(ctx context.Context, root, appDir string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	engines := map[string]string{}
	remaining := maxRailsRouteFiles
	for _, directory := range []string{"components", "engines"} {
		relative, err := filepath.Rel(root, filepath.Join(appDir, directory))
		if err != nil {
			return nil, err
		}
		base, ok := langtools.ResolveProcessPath(root, "/", relative)
		if !ok || !langtools.PathWithinBoundary(appDir, base) {
			continue
		}
		dir, err := os.Open(base)
		if err != nil {
			continue
		}
		entries, _ := dir.ReadDir(remaining)
		_ = dir.Close()
		remaining -= len(entries)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !entry.IsDir() {
				continue
			}
			relative, err := filepath.Rel(root, filepath.Join(base, entry.Name(), "config", "routes.rb"))
			if err != nil {
				return nil, err
			}
			path, ok := langtools.ResolveProcessPath(root, "/", relative)
			if !ok || !langtools.PathWithinBoundary(filepath.Join(base, entry.Name()), path) {
				continue
			}
			name, err := readRailsEngineName(ctx, path)
			if err != nil {
				return nil, err
			}
			if name == "" {
				continue
			}
			// Without executing Ruby, we cannot tell which duplicate Rails would load.
			if _, duplicate := engines[name]; duplicate {
				engines[name] = ""
			} else {
				engines[name] = path
			}
		}
		if remaining == 0 {
			break
		}
	}
	return engines, nil
}

func readRailsEngineName(ctx context.Context, path string) (string, error) {
	file, _ := langtools.OpenMetadataFile(path, maxRailsFileBytes)
	if file == nil {
		return "", nil
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, maxRailsFileBytes))
	scanner.Buffer(nil, int(maxRailsFileBytes))
	inComment := false
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "=begin") {
			inComment = true
		}
		if inComment {
			if strings.HasPrefix(line, "=end") {
				inComment = false
			}
			continue
		}
		line = stripRailsComment(line)
		if line == "" {
			continue
		}
		if match := railsEngineRoutes.FindStringSubmatch(line); match != nil {
			return match[1], nil
		}
		// Do not infer a receiver from a nested or dynamically constructed route set.
		return "", nil
	}
	return "", scanner.Err()
}
