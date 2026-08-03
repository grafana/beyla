// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"errors"
	"fmt"
	"time"
	"unicode"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

type LogEnricherConfig struct {
	// Services specifies the services to enable log enrichment for
	Services []LogEnricherServiceConfig `yaml:"services"`

	// FieldNames defines the trace context field names OBI preserves when present and injects when missing
	FieldNames LogEnricherFieldNames `yaml:"field_names"`

	// PlainText configures trace context annotation for non-JSON logs
	PlainText LogEnricherPlainTextConfig `yaml:"plain_text"`

	// CacheTTL defines the TTL for cached file descriptors
	// Default: 30m
	CacheTTL time.Duration `yaml:"cache_ttl" validate:"gt=1m" env:"OTEL_EBPF_BPF_LOG_ENRICHER_CACHE_TTL"`

	// CacheSize defines the maximum number of cached file descriptors
	// Default: 128
	CacheSize int `yaml:"cache_size" validate:"gt=64" env:"OTEL_EBPF_BPF_LOG_ENRICHER_CACHE_SIZE"`

	// AsyncWriterWorkers defines the number of shards for the async log writer
	// Default: 8
	AsyncWriterWorkers int `yaml:"async_writer_workers" validate:"gt=0" env:"OTEL_EBPF_BPF_LOG_ENRICHER_ASYNC_WRITER_WORKERS"`

	// AsyncWriterChannelLen defines the capacity of every shard's channel for the async log writer
	// Default: 500
	AsyncWriterChannelLen int `yaml:"async_writer_channel_len" validate:"gt=100" env:"OTEL_EBPF_BPF_LOG_ENRICHER_ASYNC_WRITER_CHANNEL_LEN"`
}

func (p LogEnricherConfig) Enabled() bool {
	return len(p.Services) > 0
}

func (p LogEnricherConfig) Validate() error {
	if err := validateLogEnricherFieldName("trace_id", p.FieldNames.TraceID); err != nil {
		return err
	}
	if err := validateLogEnricherFieldName("span_id", p.FieldNames.SpanID); err != nil {
		return err
	}
	if p.FieldNames.TraceID == p.FieldNames.SpanID {
		return errors.New("log_enricher field names must be distinct")
	}

	switch p.PlainText.Placement {
	case LogEnricherPlacementPrefix, LogEnricherPlacementSuffix:
	default:
		return fmt.Errorf("invalid log_enricher plain text placement %q", p.PlainText.Placement)
	}

	switch p.PlainText.Multiline {
	case LogEnricherMultilineFirstLine, LogEnricherMultilineLastLine, LogEnricherMultilineEachLine:
	default:
		return fmt.Errorf("invalid log_enricher plain text multiline mode %q", p.PlainText.Multiline)
	}

	return nil
}

func validateLogEnricherFieldName(field, value string) error {
	if value == "" {
		return fmt.Errorf("log_enricher field name %q must not be empty", field)
	}

	for _, r := range value {
		if r == '=' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("log_enricher field name %s contains an invalid character", field)
		}
	}

	return nil
}

type LogEnricherFieldNames struct {
	// TraceID is the literal trace ID field name used to preserve and inject trace context
	TraceID string `yaml:"trace_id" jsonschema:"minLength=1,pattern=^[^=\\u0000-\\u0020\\u007F-\\u00A0\\u1680\\u2000-\\u200A\\u2028-\\u2029\\u202F\\u205F\\u3000]+$"`

	// SpanID is the literal span ID field name used to preserve and inject span context
	SpanID string `yaml:"span_id" jsonschema:"minLength=1,pattern=^[^=\\u0000-\\u0020\\u007F-\\u00A0\\u1680\\u2000-\\u200A\\u2028-\\u2029\\u202F\\u205F\\u3000]+$"`
}

type LogEnricherPlacement string

const (
	LogEnricherPlacementPrefix LogEnricherPlacement = "prefix"
	LogEnricherPlacementSuffix LogEnricherPlacement = "suffix"
)

type LogEnricherMultiline string

const (
	LogEnricherMultilineFirstLine LogEnricherMultiline = "first_line"
	LogEnricherMultilineLastLine  LogEnricherMultiline = "last_line"
	LogEnricherMultilineEachLine  LogEnricherMultiline = "each_line"
)

type LogEnricherPlainTextConfig struct {
	// Enabled controls trace context annotation for non-JSON logs
	Enabled bool `yaml:"enabled"`

	// Placement controls whether fields are added before or after each selected line
	Placement LogEnricherPlacement `yaml:"placement" validate:"oneof=prefix suffix"`

	// Multiline controls which nonempty lines in each write are annotated
	Multiline LogEnricherMultiline `yaml:"multiline" validate:"oneof=first_line last_line each_line"`
}

type LogEnricherServiceConfig struct {
	// Service should also be contained in 'services' in the Discovery section
	Service services.GlobDefinitionCriteria `yaml:"service" validate:"required"`
}
