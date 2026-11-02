// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

type ignoreMode uint8

const (
	ignoreMetrics                 ignoreMode = 0x1
	ignoreTraces                  ignoreMode = 0x2
	ignoreDurations               ignoreMode = 0x4
	ignoreServiceGraphClientCount ignoreMode = 0x8
)

func setIgnoreFlag(s *Span, flag ignoreMode) {
	s.Flags |= uint8(flag)
}

func isIgnored(s *Span, flag ignoreMode) bool {
	return (s.Flags & uint8(flag)) == uint8(flag)
}

func SetIgnoreMetrics(s *Span) {
	setIgnoreFlag(s, ignoreMetrics)
}

func SetIgnoreTraces(s *Span) {
	setIgnoreFlag(s, ignoreTraces)
}

func IgnoreMetrics(s *Span) bool {
	return isIgnored(s, ignoreMetrics)
}

func IgnoreTraces(s *Span) bool {
	return isIgnored(s, ignoreTraces)
}

func SetIgnoreDurations(s *Span) {
	setIgnoreFlag(s, ignoreDurations)
}

// IgnoreDurations reports whether this span's duration is unusable. An OTel histogram
// publishes its own count, so admitting a span to that count also puts it in a bucket.
func IgnoreDurations(s *Span) bool {
	return isIgnored(s, ignoreDurations)
}

// SetIgnoreServiceGraphClientCount suppresses the client's service graph request count.
func SetIgnoreServiceGraphClientCount(s *Span) {
	setIgnoreFlag(s, ignoreServiceGraphClientCount)
}

func IgnoreServiceGraphClientCount(s *Span) bool {
	return isIgnored(s, ignoreServiceGraphClientCount)
}
