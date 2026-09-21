// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools // import "go.opentelemetry.io/obi/pkg/internal/phptools"

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	composerRootPlaceholder          = "__root__"
	composerVersionPlaceholder       = "1.0.0+no-version-set"
	maxComposerJSONBytes       int64 = 2 * 1024 * 1024
	maxInstalledPHPBytes       int64 = 8 * 1024 * 1024
)

var (
	installedRootPattern = regexp.MustCompile(
		`(?m)['"]root['"]\s*=>\s*(?:array\s*\(|\[)`,
	)
	installedVersionsPattern = regexp.MustCompile(
		`(?m)['"]versions['"]\s*=>\s*(?:array\s*\(|\[)`,
	)
	installedNamePattern = regexp.MustCompile(
		`(?m)^[\t ]*['"]name['"][\t ]*=>[\t ]*'((?:\\.|[^'\\])*)',?[\t ]*$`,
	)
	installedVersionPattern = regexp.MustCompile(
		`(?m)^[\t ]*['"]pretty_version['"][\t ]*=>[\t ]*'((?:\\.|[^'\\])*)',?[\t ]*$`,
	)
)

type composerMetadata struct {
	name                string
	version             string
	requirePackages     map[string]string
	flexRequirePackages map[string]string
}

// we prefer installed.php names, we read composer.json as fallback. if some data isn't found from installed.php
// we back fill it from composer.json.
func inspectProject(dir string) (ProjectMetadata, bool) {
	installed, installedOK := readInstalledPHP(filepath.Join(dir, "vendor", "composer", "installed.php"))
	composer, composerOK := readComposerJSON(filepath.Join(dir, "composer.json"))
	if !installedOK && !composerOK {
		return ProjectMetadata{}, false
	}

	project := ProjectMetadata{Root: dir, Name: installed.name, Version: installed.version}
	if _, ok := composerName(project.Name); !ok {
		project.Name = composer.name
	}
	if _, ok := composerVersion(project.Version); !ok {
		project.Version = composer.version
	}
	if fallbackName, ok := symfonyProjectName(dir, composer); ok {
		project.FallbackName = fallbackName
		if symfonyTemplateName(project.Name) {
			project.Name = composer.name
		}
		if symfonyTemplateName(project.Name) {
			project.Name = ""
		}
	}
	if fallbackName, ok := laravelProjectName(dir, composer); ok {
		project.FallbackName = fallbackName
		if laravelTemplateName(project.Name) {
			project.Name = composer.name
		}
		if laravelTemplateName(project.Name) {
			project.Name = ""
		}
	}
	return project, true
}

func readComposerJSON(path string) (composerMetadata, bool) {
	data, _, err := langtools.ReadMetadataFile(path, maxComposerJSONBytes)
	if err != nil || data == nil {
		return composerMetadata{}, false
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return composerMetadata{}, false
	}

	var metadata composerMetadata
	_ = json.Unmarshal(fields["name"], &metadata.name)
	_ = json.Unmarshal(fields["version"], &metadata.version)
	_ = json.Unmarshal(fields["require"], &metadata.requirePackages)
	_ = json.Unmarshal(fields["flex-require"], &metadata.flexRequirePackages)
	return metadata, true
}

func readInstalledPHP(path string) (composerMetadata, bool) {
	data, _, err := langtools.ReadMetadataFile(path, maxInstalledPHPBytes)
	if err != nil || data == nil {
		return composerMetadata{}, false
	}

	root := installedRootPattern.FindIndex(data)
	if len(root) < 2 {
		return composerMetadata{}, false
	}
	versions := installedVersionsPattern.FindIndex(data[root[1]:])
	if versions == nil {
		return composerMetadata{}, false
	}
	section := data[root[1] : root[1]+versions[0]]

	return composerMetadata{
		name:    installedField(section, installedNamePattern),
		version: installedField(section, installedVersionPattern),
	}, true
}

func installedField(section []byte, pattern *regexp.Regexp) string {
	match := pattern.FindSubmatch(section)
	if len(match) != 2 {
		return ""
	}
	return unescapePHPString(string(match[1]))
}

// unescapePHPString removes double \ and turns \' to '
// for example: acme\\payments\'api\q becomes acme\payments'api\q
func unescapePHPString(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 >= len(value) {
			out.WriteByte(value[i])
			continue
		}

		next := value[i+1]
		if next == '\\' || next == '\'' {
			out.WriteByte(next)
			i++
			continue
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

func composerName(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == composerRootPlaceholder {
		return "", false
	}
	return inferredName(value)
}

func composerVersion(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || value == composerVersionPlaceholder || strings.ContainsFunc(value, unicode.IsControl) {
		return "", false
	}
	return value, true
}
