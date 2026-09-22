// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools // import "go.opentelemetry.io/obi/pkg/internal/phptools"

import (
	"path/filepath"
	"strings"
)

const (
	laravelFrameworkPackage = "laravel/framework"
	laravelSkeletonPackage  = "laravel/laravel"
)

func laravelProjectName(dir string, composer composerMetadata) (string, bool) {
	if _, ok := composer.requirePackages[laravelFrameworkPackage]; !ok {
		return "", false
	}
	return inferredName(filepath.Base(filepath.Clean(dir)))
}

func laravelTemplateName(value string) bool {
	return strings.TrimSpace(value) == laravelSkeletonPackage
}
