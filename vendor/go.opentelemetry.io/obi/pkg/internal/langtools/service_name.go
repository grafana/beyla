// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package langtools // import "go.opentelemetry.io/obi/pkg/internal/langtools"

import (
	"path/filepath"
	"strings"
	"unicode"
)

// ValidServiceName reports whether value is usable as an inferred service name.
func ValidServiceName(value string) bool {
	return value != "" && value != "." && value != ".." && value != "-" &&
		value != string(filepath.Separator) && !strings.ContainsFunc(value, unicode.IsControl)
}
