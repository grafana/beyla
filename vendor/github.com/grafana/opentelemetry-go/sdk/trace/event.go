// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package trace // import "github.com/grafana/opentelemetry-go/sdk/trace"

import (
	"time"

	"github.com/grafana/opentelemetry-go/attribute"
)

// Event is a thing that happened during a Span's lifetime.
type Event struct {
	// Name is the name of this event
	Name string

	// Attributes describe the aspects of the event.
	Attributes []attribute.KeyValue

	// DroppedAttributeCount is the number of attributes that were not
	// recorded due to configured limits being reached.
	DroppedAttributeCount int

	// Time at which this event was recorded.
	Time time.Time
}
