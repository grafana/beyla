// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"fmt"
	"slices"

	"go.yaml.in/yaml/v3"
)

func unmarshalEnum[T ~string](value *yaml.Node, name string, dst *T, allowed ...T) error {
	if value.Tag == "!!null" {
		*dst = ""
		return nil
	}
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("%s must be a scalar, got %v", name, value.Kind)
	}
	candidate := T(value.Value)
	if slices.Contains(allowed, candidate) {
		*dst = candidate
		return nil
	}
	return fmt.Errorf("invalid %s %q", name, value.Value)
}
