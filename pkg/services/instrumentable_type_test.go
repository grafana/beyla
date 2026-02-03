package services

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func TestInstrumentableType_UnmarshalText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected svc.InstrumentableType
		wantErr  bool
	}{
		{
			name:     "java lowercase",
			input:    "java",
			expected: svc.InstrumentableJava,
			wantErr:  false,
		},
		{
			name:     "java uppercase",
			input:    "JAVA",
			expected: svc.InstrumentableJava,
			wantErr:  false,
		},
		{
			name:     "java mixed case",
			input:    "Java",
			expected: svc.InstrumentableJava,
			wantErr:  false,
		},
		{
			name:     "dotnet",
			input:    "dotnet",
			expected: svc.InstrumentableDotnet,
			wantErr:  false,
		},
		{
			name:     "dotnet uppercase",
			input:    "DOTNET",
			expected: svc.InstrumentableDotnet,
			wantErr:  false,
		},
		{
			name:     "nodejs",
			input:    "nodejs",
			expected: svc.InstrumentableNodejs,
			wantErr:  false,
		},
		{
			name:     "nodejs uppercase",
			input:    "NODEJS",
			expected: svc.InstrumentableNodejs,
			wantErr:  false,
		},
		{
			name:     "go",
			input:    "go",
			expected: svc.InstrumentableGolang,
			wantErr:  false,
		},
		{
			name:     "golang",
			input:    "golang",
			expected: svc.InstrumentableGolang,
			wantErr:  false,
		},
		{
			name:     "python",
			input:    "python",
			expected: svc.InstrumentablePython,
			wantErr:  false,
		},
		{
			name:     "ruby",
			input:    "ruby",
			expected: svc.InstrumentableRuby,
			wantErr:  false,
		},
		{
			name:     "rust",
			input:    "rust",
			expected: svc.InstrumentableRust,
			wantErr:  false,
		},
		{
			name:     "php",
			input:    "php",
			expected: svc.InstrumentablePHP,
			wantErr:  false,
		},
		{
			name:     "generic",
			input:    "generic",
			expected: svc.InstrumentableGeneric,
			wantErr:  false,
		},
		{
			name:     "unknown language",
			input:    "cobol",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var it InstrumentableType
			err := it.UnmarshalText([]byte(tt.input))

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, it.InstrumentableType)
			}
		})
	}
}

func TestInstrumentableType_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		input    InstrumentableType
		expected string
	}{
		{
			name:     "java",
			input:    InstrumentableType{InstrumentableType: svc.InstrumentableJava},
			expected: "java",
		},
		{
			name:     "dotnet",
			input:    InstrumentableType{InstrumentableType: svc.InstrumentableDotnet},
			expected: "dotnet",
		},
		{
			name:     "nodejs",
			input:    InstrumentableType{InstrumentableType: svc.InstrumentableNodejs},
			expected: "nodejs",
		},
		{
			name:     "go",
			input:    InstrumentableType{InstrumentableType: svc.InstrumentableGolang},
			expected: "go",
		},
		{
			name:     "python",
			input:    InstrumentableType{InstrumentableType: svc.InstrumentablePython},
			expected: "python",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.input.MarshalText()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestInstrumentableType_YAML(t *testing.T) {
	type Config struct {
		// nolint:undoc
		SDKs []InstrumentableType `yaml:"sdks"`
	}

	yamlData := `
sdks:
  - java
  - dotnet
  - nodejs
`

	var config Config
	err := yaml.Unmarshal([]byte(yamlData), &config)
	require.NoError(t, err)

	assert.Len(t, config.SDKs, 3)
	assert.Equal(t, svc.InstrumentableJava, config.SDKs[0].InstrumentableType)
	assert.Equal(t, svc.InstrumentableDotnet, config.SDKs[1].InstrumentableType)
	assert.Equal(t, svc.InstrumentableNodejs, config.SDKs[2].InstrumentableType)

	// Test marshaling back
	marshaled, err := yaml.Marshal(config)
	require.NoError(t, err)
	assert.Contains(t, string(marshaled), "java")
	assert.Contains(t, string(marshaled), "dotnet")
	assert.Contains(t, string(marshaled), "nodejs")
}

func TestInstrumentableType_JSON(t *testing.T) {
	type Config struct {
		SDKs []InstrumentableType `json:"sdks"`
	}

	jsonData := `{"sdks":["java","dotnet","nodejs"]}`

	var config Config
	err := json.Unmarshal([]byte(jsonData), &config)
	require.NoError(t, err)

	assert.Len(t, config.SDKs, 3)
	assert.Equal(t, svc.InstrumentableJava, config.SDKs[0].InstrumentableType)
	assert.Equal(t, svc.InstrumentableDotnet, config.SDKs[1].InstrumentableType)
	assert.Equal(t, svc.InstrumentableNodejs, config.SDKs[2].InstrumentableType)

	// Test marshaling back
	marshaled, err := json.Marshal(config)
	require.NoError(t, err)
	assert.JSONEq(t, jsonData, string(marshaled))
}

func TestParseInstrumentableType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected svc.InstrumentableType
		wantErr  bool
	}{
		{
			name:     "valid java",
			input:    "java",
			expected: svc.InstrumentableJava,
			wantErr:  false,
		},
		{
			name:     "valid dotnet",
			input:    "dotnet",
			expected: svc.InstrumentableDotnet,
			wantErr:  false,
		},
		{
			name:     "invalid language",
			input:    "fortran",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseInstrumentableType(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
