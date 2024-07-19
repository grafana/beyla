// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package trace // import "github.com/grafana/opentelemetry-go/sdk/trace"

import (
	"github.com/grafana/opentelemetry-go/attribute"
	"github.com/grafana/opentelemetry-go/trace"
)

// Link is the relationship between two Spans. The relationship can be within
// the same Trace or across different Traces.
type Link struct {
	// SpanContext of the linked Span.
	SpanContext trace.SpanContext

	// Attributes describe the aspects of the link.
	Attributes []attribute.KeyValue

	// DroppedAttributeCount is the number of attributes that were not
	// recorded due to configured limits being reached.
	DroppedAttributeCount int
}
