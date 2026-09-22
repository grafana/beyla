// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools // import "go.opentelemetry.io/obi/pkg/internal/phptools"

import (
	"path/filepath"
	"strings"
)

const (
	symfonyFrameworkBundlePackage = "symfony/framework-bundle"
	symfonyFrameworkPackage       = "symfony/symfony"
	symfonySkeletonPackage        = "symfony/skeleton"
)

func symfonyProjectName(dir string, composer composerMetadata) (string, bool) {
	if !composerIdentifiesSymfony(composer) {
		return "", false
	}
	return inferredName(filepath.Base(filepath.Clean(dir)))
}

func composerIdentifiesSymfony(composer composerMetadata) bool {
	return requiresSymfony(composer.requirePackages) || requiresSymfony(composer.flexRequirePackages)
}

func requiresSymfony(packages map[string]string) bool {
	_, frameworkBundle := packages[symfonyFrameworkBundlePackage]
	_, framework := packages[symfonyFrameworkPackage]
	return frameworkBundle || framework
}

func symfonyTemplateName(value string) bool {
	return strings.TrimSpace(value) == symfonySkeletonPackage
}
