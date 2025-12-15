// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package integration provides reusable integration test utilities
// for downstream projects, whilst allowing each project to maintain their own
// project-specific configuration.
//
// Example usage:
//
//	config := &integration.TestConfig{
//	    EnvPrefix:          "MY_PROJECT_",
//	    ComposeServiceName: "my-service",
//	    MetricPrefix:       "myproject",
//	    // ... other project-specific settings
//	}
//	integration.InternalPrometheusExport(t, config)
//
// For OBI, use the provided DefaultOBIConfig() function.
package integration
