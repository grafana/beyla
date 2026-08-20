// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import (
	"strings"
	"unicode/utf8"
)

// SanitizeUTF8 returns s with invalid UTF-8 sequences removed, or s itself when
// it is already valid. Invalid bytes are dropped rather than replaced, so
// distinct inputs may sanitize to the same value, and a wholly invalid input
// sanitizes to the empty string.
func SanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "")
}
