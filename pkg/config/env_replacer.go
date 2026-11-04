package config

import (
	"bytes"
	"os"
	"regexp"
)

var envVarRegex = regexp.MustCompile(`\$?\${(?:env:)?([a-zA-Z_][a-zA-Z0-9_]*)(?::-([^}]*))?}`)

func ReplaceEnv(content []byte) []byte {
	return ReplaceEnvFrom(content, os.Getenv)
}

// ReplaceEnvFrom replaces the environment variables in content with the values returned by getenv.
func ReplaceEnvFrom(content []byte, getenv func(string) string) []byte {
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
		envValue := getenv(envName)
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
