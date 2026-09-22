// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"os"
	"path/filepath"
	"strings"
)

func legacySymfonyYAMLEntries(projectRoot string) []string {
	configDirectory := filepath.Join(projectRoot, "app", "config")
	return existingFiles(
		filepath.Join(configDirectory, "routing.yaml"),
		filepath.Join(configDirectory, "routing.yml"),
	)
}

func legacySymfonyXMLEntries(projectRoot string) []string {
	configDirectory := filepath.Join(projectRoot, "app", "config")
	entries := existingFiles(filepath.Join(configDirectory, "routing.xml"))

	files, err := os.ReadDir(filepath.Join(configDirectory, "routing"))
	if err != nil {
		return entries
	}

	for _, file := range files {
		if file.Type().IsRegular() && strings.EqualFold(filepath.Ext(file.Name()), ".xml") {
			entries = append(entries, filepath.Join(configDirectory, "routing", file.Name()))
		}
	}

	return entries
}
