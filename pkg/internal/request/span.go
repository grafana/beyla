package request

import (
	obispan "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
)

type ignoreMode uint8

const (
	ignoreMetrics ignoreMode = 0x1
	ignoreTraces  ignoreMode = 0x2
)

func setIgnoreFlag(s *obispan.Span, flag ignoreMode) {
	s.Flags |= uint8(flag)
}

func isIgnored(s *obispan.Span, flag ignoreMode) bool {
	return (s.Flags & uint8(flag)) == uint8(flag)
}

func SetIgnoreMetrics(s *obispan.Span) {
	setIgnoreFlag(s, ignoreMetrics)
}

func SetIgnoreTraces(s *obispan.Span) {
	setIgnoreFlag(s, ignoreTraces)
}

func IgnoreMetrics(s *obispan.Span) bool {
	return isIgnored(s, ignoreMetrics)
}

func IgnoreTraces(s *obispan.Span) bool {
	return isIgnored(s, ignoreTraces)
}
