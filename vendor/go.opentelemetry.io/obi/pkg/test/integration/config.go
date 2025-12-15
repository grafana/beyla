// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

// TestConfig holds project-specific configuration for integration tests
type TestConfig struct {
	// Environment variable prefixes
	EnvPrefix string

	// Docker compose configuration
	ComposeServiceName string
	ComposeImageName   string
	DockerfilePath     string
	ConfigPath         string

	// Metric naming
	MetricPrefix string
	IPAttribute  string

	// Telemetry SDK attributes
	SDKName    string
	VersionPkg string
}

// DefaultOBIConfig returns the default OBI test configuration
func DefaultOBIConfig() *TestConfig {
	return &TestConfig{
		EnvPrefix:          "OTEL_EBPF_",
		ComposeServiceName: "obi",
		ComposeImageName:   "hatest-obi",
		DockerfilePath:     "ebpf-instrument/Dockerfile",
		ConfigPath:         "obi-config.yml",
		MetricPrefix:       "obi",
		IPAttribute:        "obi.ip",
		SDKName:            "opentelemetry-ebpf-instrumentation",
		VersionPkg:         "obibuildinfo.Version",
	}
}
