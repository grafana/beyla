// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"os"
	"path/filepath"
	"strings"
)

func symfonyConfigEntries(projectRoot string) []string {
	configDirectory := filepath.Join(projectRoot, "config")

	entries := existingFiles(
		filepath.Join(configDirectory, "routes.yaml"),
		filepath.Join(configDirectory, "routes.yml"),
		filepath.Join(configDirectory, "routes.xml"),
	)

	files, err := os.ReadDir(filepath.Join(configDirectory, "routes"))
	if err != nil {
		return entries
	}

	for _, file := range files {
		if file.Type().IsRegular() && isSymfonyConfigFile(file.Name()) {
			entries = append(entries, filepath.Join(configDirectory, "routes", file.Name()))
		}
	}

	return entries
}

func isSymfonyConfigFile(path string) bool {
	return isYAMLFile(path) || isXMLFile(path)
}

func localSymfonyResource(projectRoot, baseDirectory, resource string) (string, bool) {
	if strings.TrimSpace(resource) == "" {
		return "", false
	}

	if filepath.IsAbs(resource) || strings.HasPrefix(resource, "@") || strings.ContainsAny(resource, "*?{}") {
		return "", false
	}

	resolvedPath := filepath.Clean(filepath.Join(baseDirectory, filepath.FromSlash(resource)))

	relativePath, err := filepath.Rel(projectRoot, resolvedPath)
	if err != nil || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return "", false
	}

	return resolvedPath, true
}

func existingFiles(paths ...string) []string {
	var files []string
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			files = append(files, path)
		}
	}

	return files
}

func isYAMLFile(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".yaml" || extension == ".yml"
}

func isXMLFile(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".xml")
}
