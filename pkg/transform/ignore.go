package transform

import "github.com/grafana/beyla/v2/pkg/internal/request"

type IgnoreMode string

const (
	// IgnoreMetrics prevents sending metric events for ignored patterns
	IgnoreMetrics = IgnoreMode("metrics")
	// IgnoreTraces prevents sending trace events for ignored patterns
	IgnoreTraces = IgnoreMode("traces")
	// IgnoreAll prevents sending both metrics and traces for ignored patterns
	IgnoreAll = IgnoreMode("all")

	IgnoreDefault = IgnoreAll
)

func setSpanIgnoreMode(mode IgnoreMode, s *request.Span) {
	switch mode {
	case IgnoreMetrics:
		s.SetIgnoreMetrics()
	case IgnoreTraces:
		s.SetIgnoreTraces()
	}
}
