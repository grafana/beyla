package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplaceEnv(t *testing.T) {
	// Set env vars for testing
	t.Setenv("TEST_VAR", "test_value")
	t.Setenv("ANOTHER_VAR", "another_value")
	t.Setenv("EMPTY_VAR", "")

	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "Simple YAML with environment variable",
			input:    []byte("key: ${TEST_VAR}\n"),
			expected: []byte("key: test_value\n"),
		},
		{
			name:     "YAML with default value when env var exists",
			input:    []byte("key: ${TEST_VAR:-default}\n"),
			expected: []byte("key: test_value\n"),
		},
		{
			name:     "YAML with default value when env var doesn't exist",
			input:    []byte("key: ${NON_EXISTENT_VAR:-default}\n"),
			expected: []byte("key: default\n"),
		},
		{
			name:     "YAML with when env var doesn't exist",
			input:    []byte("key: ${NON_EXISTENT_VAR}\n"),
			expected: []byte("key: \n"),
		},
		{
			name:     "YAML with empty default value when env var doesn't exist",
			input:    []byte("key: ${NON_EXISTENT_VAR:-}\n"),
			expected: []byte("key: \n"),
		},
		{
			name:     "YAML with escaped environment variable",
			input:    []byte("key: $${TEST_VAR}\n"),
			expected: []byte("key: ${TEST_VAR}\n"),
		},
		{
			name:     "YAML with multiple environment variables",
			input:    []byte("key1: ${TEST_VAR}\nkey2: ${ANOTHER_VAR}\n"),
			expected: []byte("key1: test_value\nkey2: another_value\n"),
		},
		{
			name:     "YAML with environment variable in the middle of a string",
			input:    []byte("key: prefix-${TEST_VAR}-suffix\n"),
			expected: []byte("key: prefix-test_value-suffix\n"),
		},
		{
			name:     "YAML with empty environment variable and no default",
			input:    []byte("key: ${EMPTY_VAR}\n"),
			expected: []byte("key: \n"),
		},
		{
			name:     "YAML with empty environment variable and default",
			input:    []byte("key: ${EMPTY_VAR:-default}\n"),
			expected: []byte("key: default\n"),
		},
		{
			name: "Complex YAML with nested structures",
			input: []byte(`
service:
  name: ${TEST_VAR}
  port: 8080
config:
  timeout: ${NON_EXISTENT_VAR:-30}
  retries: 3
  credentials:
    username: admin
    password: $${PASSWORD}
`),
			expected: []byte(`
service:
  name: test_value
  port: 8080
config:
  timeout: 30
  retries: 3
  credentials:
    username: admin
    password: ${PASSWORD}
`),
		},
		{
			name:     "YAML with 'env:' prefix in variable",
			input:    []byte("key: ${env:TEST_VAR}\n"),
			expected: []byte("key: test_value\n"),
		},
		{
			name:     "YAML with 'env:' prefix in nonexisting variable",
			input:    []byte("key: ${env:TEST_VAR_UNEXISTING}\n"),
			expected: []byte("key: \n"),
		},
		{
			name:     "YAML with no replacements",
			input:    []byte("key: value\n"),
			expected: []byte("key: value\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReplaceEnv(tt.input)
			assert.Equal(t, string(tt.expected), string(result))
		})
	}
}
