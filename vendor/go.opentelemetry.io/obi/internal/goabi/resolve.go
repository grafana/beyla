// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi // import "go.opentelemetry.io/obi/internal/goabi"

import (
	"fmt"

	"go.opentelemetry.io/obi/internal/goversion"
)

// FromLookup loads and validates a complete ABI using lookup as its source.
func FromLookup(
	targetVersion goversion.Version,
	lookup func(Requirement) (uint64, error),
) (ABI, error) {
	requested, err := requiredDefinitions(targetVersion)
	if err != nil {
		return ABI{}, err
	}
	return loadAndValidate(requested, lookup)
}

func loadAndValidate(
	requested []definition,
	lookup func(Requirement) (uint64, error),
) (ABI, error) {
	abi := ABI{facts: make([]Fact, 0, len(requested))}
	for _, definition := range requested {
		requirement := definition.Requirement
		value, err := lookup(requirement)
		if err != nil {
			return ABI{}, fmt.Errorf("loading Go ABI fact %s: %w", requirement.Key(), err)
		}
		definition.assign(&abi, value)
		abi.facts = append(abi.facts, Fact{Requirement: requirement, Value: value})
	}

	if abi.TypeMetadata == nil {
		return abi, nil
	}
	if err := validateTypeMetadata(abi.TypeMetadata); err != nil {
		return ABI{}, err
	}
	return abi, nil
}
