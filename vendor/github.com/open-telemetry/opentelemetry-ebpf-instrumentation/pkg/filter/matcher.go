package filter

import (
	"errors"

	"github.com/gobwas/glob"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
)

// Matcher condition for a given field of the record type T.
type Matcher[T any] struct {
	// Glob will be compared with the value of the field
	Glob glob.Glob
	// Negate the condition value
	Negate bool
	// Getter for the field to be compared with the Glob
	Getter attributes.Getter[T, string]
}

func (m *Matcher[T]) Matches(record T) bool {
	matches := m.Glob.Match(m.Getter(record))
	return m.Negate != matches
}

// MatchDefinition stores the user-provided definition for the
// record filtering.
type MatchDefinition struct {
	// Match stores the glob that a given attribute must match to let the record pass
	Match string `yaml:"match"`
	// NotMatch stores the glob that a given attribute MUST NOT match to let the record pass
	NotMatch string `yaml:"not_match"`
}

func (md *MatchDefinition) Validate() error {
	if md.Match == "" && md.NotMatch == "" {
		return errors.New("attribute must include a match or a not_match clause")
	}
	if md.Match != "" && md.NotMatch != "" {
		return errors.New("attribute can't include bot match or not_match clauses")
	}
	return nil
}
