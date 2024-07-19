// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otlptracehttp // import "github.com/grafana/opentelemetry-go/exporters/otlp/otlptrace/otlptracehttp"

import (
	"context"

	"github.com/grafana/opentelemetry-go/exporters/otlp/otlptrace"
)

// New constructs a new Exporter and starts it.
func New(ctx context.Context, opts ...Option) (*otlptrace.Exporter, error) {
	return otlptrace.New(ctx, NewClient(opts...))
}

// NewUnstarted constructs a new Exporter and does not start it.
func NewUnstarted(opts ...Option) *otlptrace.Exporter {
	return otlptrace.NewUnstarted(NewClient(opts...))
}
