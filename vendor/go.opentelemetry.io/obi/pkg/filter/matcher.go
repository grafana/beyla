// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter // import "go.opentelemetry.io/obi/pkg/filter"

import (
	"errors"
	"strconv"

	"github.com/gobwas/glob"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

// Matcher condition for a given field of the record type T.
type Matcher[T any] struct {
	// Glob will be compared with the value of the field
	Glob glob.Glob
	// Negate the condition value
	Negate bool
	// Getter for the field to be compared with the Glob
	Getter attributes.Getter[T, string]

	// Numeric matchers
	GreaterEquals *int
	GreaterThan   *int
	Equals        *int
	NotEquals     *int
	LessEquals    *int
	LessThan      *int
}

func (m *Matcher[T]) Matches(record T) bool {
	valueStr := m.Getter(record)

	if m.Equals != nil || m.NotEquals != nil || m.LessEquals != nil ||
		m.LessThan != nil || m.GreaterThan != nil || m.GreaterEquals != nil {
		value, err := strconv.Atoi(valueStr)
		if err != nil {
			return false
		}

		if m.Equals != nil && value != *m.Equals {
			return false
		}

		if m.NotEquals != nil && value == *m.NotEquals {
			return false
		}

		if m.GreaterEquals != nil && value < *m.GreaterEquals {
			return false
		}

		if m.GreaterThan != nil && value <= *m.GreaterThan {
			return false
		}

		if m.LessEquals != nil && value > *m.LessEquals {
			return false
		}

		if m.LessThan != nil && value >= *m.LessThan {
			return false
		}

		return true
	}

	matches := m.Glob.Match(valueStr)
	return m.Negate != matches
}

// MatchDefinition stores the user-provided definition for the
// record filtering.
type MatchDefinition struct {
	// Match stores the glob that a given attribute must match to let the record pass
	Match string `yaml:"match"`
	// NotMatch stores the glob that a given attribute MUST NOT match to let the record pass
	NotMatch string `yaml:"not_match"`
	// Numerical comparison for e.g. http.code or timings
	GreaterThan   *int `yaml:"greater_than"`
	GreaterEquals *int `yaml:"greater_equals"`
	Equals        *int `yaml:"equals"`
	NotEquals     *int `yaml:"not_equals"`
	LessEquals    *int `yaml:"less_equals"`
	LessThan      *int `yaml:"less_than"`
}

func (md *MatchDefinition) Validate() error {
	hasGlob := md.Match != "" || md.NotMatch != ""
	hasNumeric := md.GreaterThan != nil || md.LessThan != nil || md.Equals != nil || md.NotEquals != nil || md.GreaterEquals != nil || md.LessEquals != nil

	if !hasGlob && !hasNumeric {
		return errors.New("attribute must include a match/not_match clause or numeric comparison")
	}
	if md.Match != "" && md.NotMatch != "" {
		return errors.New("attribute can't include bot match or not_match clauses")
	}
	return nil
}
