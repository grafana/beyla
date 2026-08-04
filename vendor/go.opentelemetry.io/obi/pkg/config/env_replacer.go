// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"bytes"
	"os"
	"regexp"
)

var envVarRegex = regexp.MustCompile(`\$?\$[\{\(](?:env:)?([a-zA-Z_][a-zA-Z0-9_]*)(?::-([^}\)]*))?[\}\)]`)

// EscapeEnv escapes substitution tokens so one ReplaceEnv pass preserves them.
func EscapeEnv(content []byte) []byte {
	return envVarRegex.ReplaceAllFunc(content, func(match []byte) []byte {
		escaped := make([]byte, 0, len(match)+1)
		escaped = append(escaped, '$')
		return append(escaped, match...)
	})
}

func ReplaceEnv(content []byte) []byte {
	// Process normal environment variable substitutions
	return envVarRegex.ReplaceAllFunc(content, func(match []byte) []byte {
		// Replaces $$-escaped env vars by single-dollar mark
		// but does not replace the contents
		if bytes.HasPrefix(match, []byte("$$")) {
			return bytes.ReplaceAll(match, []byte("$$"), []byte{'$'})
		}
		// Logic to extract and replace ENV-NAME with its value or DEFAULT-VALUE

		matches := envVarRegex.FindStringSubmatch(string(match))
		envName := matches[1]
		defaultValue := ""
		if len(matches) > 2 {
			defaultValue = matches[2]
		}

		// Get environment variable value
		envValue := os.Getenv(envName)
		if envValue == "" && defaultValue != "" {
			envValue = defaultValue
		}

		// Keep the prefix that was matched to avoid replacing $ in the prefix
		prefix := match[:1]
		if prefix[0] != '$' {
			return append(prefix, []byte(envValue)...)
		}
		return []byte(envValue)
	})
}
