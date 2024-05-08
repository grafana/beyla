// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otlpexporter // import "go.opentelemetry.io/collector/exporter/otlpexporter"

import (
	"errors"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
)

// Config defines configuration for OTLP exporter.
type Config struct {
	exporterhelper.TimeoutSettings `mapstructure:",squash"`     // squash ensures fields are correctly decoded in embedded struct.
	QueueConfig                    exporterhelper.QueueSettings `mapstructure:"sending_queue"`
	RetryConfig                    configretry.BackOffConfig    `mapstructure:"retry_on_failure"`

	configgrpc.ClientConfig `mapstructure:",squash"` // squash ensures fields are correctly decoded in embedded struct.
}

func (c *Config) Validate() error {
	if c.sanitizedEndpoint() == "" {
		return errors.New(`requires a non-empty "endpoint"`)
	}
	return nil
}

func (c *Config) sanitizedEndpoint() string {
	switch {
	case strings.HasPrefix(c.Endpoint, "http://"):
		return strings.TrimPrefix(c.Endpoint, "http://")
	case strings.HasPrefix(c.Endpoint, "https://"):
		return strings.TrimPrefix(c.Endpoint, "https://")
	default:
		return c.Endpoint
	}
}

var _ component.Config = (*Config)(nil)
