// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

type ignoreMode uint8

const (
	ignoreMetrics ignoreMode = 0x1
	ignoreTraces  ignoreMode = 0x2
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
