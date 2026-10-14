// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"encoding/json"
	"maps"
	"path/filepath"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const maxComposerBytes int64 = 2 * 1024 * 1024

type frameworks struct {
	laravel     bool
	symfony     bool
	slim        bool
	fosRest     bool
	apiPlatform bool
}

func readFrameworks(root string) (frameworks, bool) {
	data, _, err := langtools.ReadMetadataFile(filepath.Join(root, "composer.json"), maxComposerBytes)
	if err != nil || data == nil {
		return frameworks{}, false
	}

	var composer struct {
		Require     map[string]string `json:"require"`
		FlexRequire map[string]string `json:"flex-require"`
	}
	if err := json.Unmarshal(data, &composer); err != nil {
		return frameworks{}, false
	}

	packages := make(map[string]string, len(composer.Require)+len(composer.FlexRequire))
	maps.Copy(packages, composer.Require)
	maps.Copy(packages, composer.FlexRequire)

	return frameworks{
		laravel:     hasPackage(packages, "laravel/framework"),
		symfony:     hasAnyPackage(packages, "symfony/framework-bundle", "symfony/symfony"),
		slim:        hasPackage(packages, "slim/slim"),
		fosRest:     hasPackage(packages, "friendsofsymfony/rest-bundle"),
		apiPlatform: hasAnyPackage(packages, "api-platform/core", "api-platform/symfony"),
	}, true
}

func hasPackage(packages map[string]string, name string) bool {
	_, ok := packages[name]
	return ok
}

func hasAnyPackage(packages map[string]string, names ...string) bool {
	for _, name := range names {
		if hasPackage(packages, name) {
			return true
		}
	}
	return false
}

func (f frameworks) supported() bool {
	return f.laravel || f.symfony || f.slim
}
