// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"fmt"
	"strconv"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration is a time.Duration that marshals to the v2 duration string format.
type Duration time.Duration

// MarshalYAML emits the duration using Go duration syntax, such as "5m0s".
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// UnmarshalYAML parses a duration from Go duration syntax, such as "5m0s".
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Tag == "!!null" {
		*d = 0
		return nil
	}
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar, got %v", value.Kind)
	}

	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", value.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

// TimeDuration returns the standard library duration value.
func (d Duration) TimeDuration() time.Duration {
	return time.Duration(d)
}

// Milliseconds is a time.Duration that marshals to a millisecond count.
type Milliseconds time.Duration

// MarshalYAML emits the duration as an integer millisecond count.
func (m Milliseconds) MarshalYAML() (any, error) {
	return time.Duration(m).Milliseconds(), nil
}

// UnmarshalYAML parses a duration from an integer millisecond count.
func (m *Milliseconds) UnmarshalYAML(value *yaml.Node) error {
	if value.Tag == "!!null" {
		*m = 0
		return nil
	}
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("milliseconds must be a scalar, got %v", value.Kind)
	}

	millis, err := strconv.ParseInt(value.Value, 10, 64)
	if err != nil {
		return fmt.Errorf("parse milliseconds %q: %w", value.Value, err)
	}
	*m = Milliseconds(time.Duration(millis) * time.Millisecond)
	return nil
}

// TimeDuration returns the standard library duration value.
func (m Milliseconds) TimeDuration() time.Duration {
	return time.Duration(m)
}
