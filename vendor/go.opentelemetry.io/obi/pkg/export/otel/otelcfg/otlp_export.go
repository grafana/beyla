// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// TracesExportFunc sends traces to a consumer in the same process.
type TracesExportFunc func(context.Context, ptrace.Traces) error

// MetricsExportFunc sends metrics to a consumer in the same process.
type MetricsExportFunc func(context.Context, pmetric.Metrics) error
