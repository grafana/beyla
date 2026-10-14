// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools // import "go.opentelemetry.io/obi/pkg/internal/phptools"

import (
	"bytes"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const maxDotEnvBytes int64 = 1024 * 1024

func readDotEnvAppName(path string) string {
	data, _, err := langtools.ReadMetadataFile(path, maxDotEnvBytes)
	if err != nil || data == nil {
		return ""
	}

	result := ""

	for line := range bytes.SplitSeq(data, []byte{'\n'}) {
		assignment := strings.TrimSpace(strings.TrimSuffix(string(line), "\r"))
		if assignment == "" || strings.HasPrefix(assignment, "#") {
			continue
		}

		key, value, ok := strings.Cut(assignment, "=")
		if !ok || strings.TrimSpace(key) != appNameEnv {
			continue
		}
		if value, ok := literalDotEnvValue(value); ok {
			result = value
		}
	}
	return result
}

// we read what's in .env, but we do some sanity checks that the name
// isn't somehow with parameters, like APP_NAME="{whatever}-something-else"
func literalDotEnvValue(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "#") {
		return "", false
	}

	if value[0] == '\'' || value[0] == '"' {
		return quotedDotEnvValue(value, value[0])
	}

	for i := 1; i < len(value); i++ {
		if value[i] == '#' && (value[i-1] == ' ' || value[i-1] == '\t') {
			value = strings.TrimSpace(value[:i])
			break
		}
	}
	if strings.Contains(value, "$") {
		return "", false
	}
	return value, value != ""
}

func quotedDotEnvValue(value string, quote byte) (string, bool) {
	var out strings.Builder
	for i := 1; i < len(value); i++ {
		if value[i] == quote {
			rest := strings.TrimSpace(value[i+1:])
			if rest != "" && !strings.HasPrefix(rest, "#") {
				return "", false
			}
			literal := out.String()
			if strings.Contains(literal, "$") {
				return "", false
			}
			return literal, true
		}

		if value[i] == '\\' && i+1 < len(value) &&
			(value[i+1] == quote || value[i+1] == '\\') {
			i++
		}
		out.WriteByte(value[i])
	}
	return "", false
}
