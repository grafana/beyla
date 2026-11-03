// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package exceptions defines the runtime-independent exception delivery boundary.
package exceptions // import "go.opentelemetry.io/obi/pkg/exceptions"

import (
	"time"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

// Event is an observation at capture time. Unknown span context remains zero.
// Producers must supply a service with resolved capture settings and resource metadata.
type Event struct {
	Service           svc.Attrs
	Timestamp         time.Time
	ObservedTimestamp time.Time
	Type              string
	Message           string
	Stacktrace        string
	TraceID           trace.TraceID
	SpanID            trace.SpanID
	TraceFlags        trace.TraceFlags
	// SeverityNumber is the OTel severity (1-24), or zero when impact is unknown.
	SeverityNumber int32
}
