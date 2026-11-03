// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import obiconfig "go.opentelemetry.io/obi/pkg/config"

// Correlation describes standalone telemetry correlation settings.
type Correlation struct {
	LogTraceAnnotation LogTraceAnnotation `yaml:"log_trace_annotation"`
}

// LogTraceAnnotation describes log trace annotation settings.
type LogTraceAnnotation struct {
	Enabled bool `yaml:"enabled"`
	// Match selects the workloads whose logs are annotated, among those the
	// capture rules select. Required when Enabled
	Match       []RuleMatch      `yaml:"match,omitempty"`
	Filter      AttributeFilters `yaml:"filter,omitempty"`
	FieldNames  FieldNames       `yaml:"field_names"`
	PlainText   PlainText        `yaml:"plain_text"`
	Cache       Cache            `yaml:"cache"`
	AsyncWriter AsyncWriter      `yaml:"async_writer"`
}

// FieldNames describes the shared output keys for trace context fields.
type FieldNames struct {
	TraceID *string `yaml:"trace_id,omitempty"`
	SpanID  *string `yaml:"span_id,omitempty"`
}

// PlainText describes trace context annotation for non-JSON logs.
type PlainText struct {
	Enabled   *bool                           `yaml:"enabled,omitempty"`
	Placement *obiconfig.LogEnricherPlacement `yaml:"placement,omitempty"`
	Multiline *obiconfig.LogEnricherMultiline `yaml:"multiline,omitempty"`
}

// AsyncWriter describes asynchronous writer worker and channel settings.
type AsyncWriter struct {
	Workers    int `yaml:"workers"`
	ChannelLen int `yaml:"channel_len"`
}
