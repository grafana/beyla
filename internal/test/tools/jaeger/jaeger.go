// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package jaeger provides some convenience data structures for integration testing.
// Disable some linting, as this is just a test class where readability is preferred to performance
package jaeger // import "go.opentelemetry.io/obi/internal/test/integration/components/jaeger"

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type Services struct {
	Data []string `json:"data"`
}

type TracesQuery struct {
	Data []Trace `json:"data"`
}

type Trace struct {
	TraceID   string             `json:"traceID"`
	Spans     []Span             `json:"spans"`
	Processes map[string]Process `json:"processes"`
}

type Span struct {
	TraceID       string      `json:"traceID"`
	SpanID        string      `json:"spanID"`
	OperationName string      `json:"operationName"`
	References    []Reference `json:"references"`
	StartTime     int64       `json:"startTime"`
	Duration      int64       `json:"duration"`
	Tags          []Tag       `json:"tags"`
	ProcessID     string      `json:"processID"`
}

type Tag struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type Reference struct {
	RefType string `json:"refType"`
	TraceID string `json:"traceID"`
	SpanID  string `json:"spanID"`
}

type Process struct {
	ServiceName string `json:"serviceName"`
	Tags        []Tag  `json:"tags"`
}

func (tq *TracesQuery) FindBySpan(tags ...Tag) []Trace {
	var matches []Trace
	for _, trace := range tq.Data {
		for i := range trace.Spans {
			span := &trace.Spans[i]
			diff := span.Diff(tags...)
			if len(diff) == 0 {
				matches = append(matches, trace)
				break
			}
		}
	}
	return matches
}

func (t *Trace) FindByOperationName(operationName string, spanType string) []Span {
	var matches []Span
	for i := range t.Spans {
		s := &t.Spans[i]
		if s.OperationName == operationName {
			tag, _ := FindIn(s.Tags, "span.kind")
			if spanType == "" || spanType == tag.Value {
				matches = append(matches, *s)
			}
		}
	}
	return matches
}

func (t *Trace) FindByOperationNameAndService(operationName, service string) []Span {
	var matches []Span
	for i := range t.Spans {
		s := &t.Spans[i]
		if s.OperationName == operationName {
			if p, ok := t.Processes[s.ProcessID]; ok {
				if p.ServiceName == service {
					matches = append(matches, *s)
				}
			}
		}
	}
	return matches
}

func (t *Trace) FindByOperationNameServiceAndKind(operationName, service, kind string) []Span {
	candidates := t.FindByOperationNameAndService(operationName, service)

	var matches []Span
	for i := range candidates {
		s := candidates[i]
		if tag, ok := FindIn(s.Tags, "span.kind"); ok && tag.Value == kind {
			matches = append(matches, s)
		}
	}
	return matches
}

func (t *Trace) ParentOf(s *Span) (Span, bool) {
	parentID := ""
	for _, ref := range s.References {
		if ref.RefType == "CHILD_OF" {
			parentID = ref.SpanID
		}
	}
	if parentID == "" {
		return Span{}, false
	}
	for i := range t.Spans {
		sp := t.Spans[i]
		if sp.SpanID == parentID {
			return sp, true
		}
	}
	return Span{}, false
}

func (t *Trace) ChildrenOf(parentID string) []Span {
	var matches []Span
	for i := range t.Spans {
		sp := t.Spans[i]
		for _, ref := range sp.References {
			if ref.RefType == "CHILD_OF" && ref.SpanID == parentID {
				matches = append(matches, sp)
				break
			}
		}
	}
	return matches
}

func (s *Span) Diff(expected ...Tag) DiffResult {
	return Diff(expected, s.Tags)
}

// DiffAsRegexp works like Diff but it matches the expected tags values
// as regular expressions
func (s *Span) DiffAsRegexp(expected ...Tag) DiffResult {
	return DiffAsRegexp(expected, s.Tags)
}

func FindIn(tags []Tag, key string) (Tag, bool) {
	for _, t := range tags {
		if t.Key == key {
			return t, true
		}
	}
	return Tag{}, false
}

// tagParseStringSlice attempts to parse a JSON-encoded string array.
// Jaeger 1.x serializes OTLP StringSlice attributes as a single string
// containing the JSON array, e.g. `["value-one","value-two"]`.
func tagParseStringSlice(s string) ([]string, bool) {
	if len(s) < 2 || s[0] != '[' {
		return nil, false
	}
	var parsed []string
	if err := json.Unmarshal([]byte(s), &parsed); err != nil {
		return nil, false
	}
	return parsed, true
}

// TagFirstStringValue extracts the first string value from a tag.
// Handles plain strings, JSON-encoded string arrays (Jaeger 1.x),
// and native array values.
func TagFirstStringValue(tag Tag) (string, bool) {
	switch v := tag.Value.(type) {
	case string:
		if vals, ok := tagParseStringSlice(v); ok && len(vals) > 0 {
			return vals[0], true
		}
		return v, true
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

// TagStringValues extracts all string values from a tag.
// Handles plain strings, JSON-encoded string arrays (Jaeger 1.x),
// and native array values.
func TagStringValues(tag Tag) []string {
	switch v := tag.Value.(type) {
	case string:
		if vals, ok := tagParseStringSlice(v); ok {
			return vals
		}
		return []string{v}
	case []any:
		result := make([]string, 0, len(v))
		for _, elem := range v {
			if s, ok := elem.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

type DiffResult []TagDiff

func (mr DiffResult) String() string {
	sb := strings.Builder{}
	if len(mr) > 0 {
		sb.WriteString("The following tags did not match:\n")
	}
	for _, td := range mr {
		switch td.ErrType {
		case ErrTypeMissing:
			fmt.Fprintf(&sb, "\tmissing tag: %+v\n", td.Expected)
		case ErrTypeNotEqual, ErrTypeNotMatching:
			fmt.Fprintf(&sb, "\ttag values do not match:\n\t\twant: %+v\n\t\tgot:  %+v\n", td.Expected, td.Actual)
		}
	}
	return sb.String()
}

type ErrType int

const (
	ErrTypeMissing = ErrType(iota)
	ErrTypeNotEqual
	ErrTypeNotMatching
)

type TagDiff struct {
	ErrType  ErrType
	Expected Tag
	Actual   Tag
}

func Diff(expected, actual []Tag) DiffResult {
	dr := DiffResult{}
	actualTags := map[string]Tag{}
	for _, d := range actual {
		actualTags[d.Key] = d
	}
	for _, exp := range expected {
		if act, ok := actualTags[exp.Key]; ok {
			if act.Type != exp.Type || act.Value != exp.Value {
				dr = append(dr, TagDiff{ErrType: ErrTypeNotEqual, Expected: exp, Actual: act})
			}
		} else {
			dr = append(dr, TagDiff{ErrType: ErrTypeMissing, Expected: exp})
		}
	}
	return dr
}

// DiffAsRegexp works like Diff but it matches the expected tags values
// as regular expressions when type is "String"
func DiffAsRegexp(expected, actual []Tag) DiffResult {
	dr := DiffResult{}
	actualTags := map[string]Tag{}
	for _, d := range actual {
		actualTags[d.Key] = d
	}
	for _, exp := range expected {
		if act, ok := actualTags[exp.Key]; ok {
			if act.Type == "string" && exp.Type == "string" {
				if !regexp.MustCompile(fmt.Sprint(exp.Value)).MatchString(fmt.Sprint(act.Value)) {
					dr = append(dr, TagDiff{ErrType: ErrTypeNotMatching, Expected: exp, Actual: act})
				}
			} else if act.Type != exp.Type || act.Value != exp.Value {
				dr = append(dr, TagDiff{ErrType: ErrTypeNotEqual, Expected: exp, Actual: act})
			}
		} else {
			dr = append(dr, TagDiff{ErrType: ErrTypeMissing, Expected: exp})
		}
	}
	return dr
}
