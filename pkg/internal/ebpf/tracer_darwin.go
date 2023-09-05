package ebpf

import (
	"context"

	"github.com/grafana/beyla/pkg/internal/request"
)

// dummy functions and types to avoid compilation errors in Darwin. The tracer component is only usable in Linux.
type ProcessTracer struct{}

func (pt *ProcessTracer) Run(_ context.Context, _ chan<- []request.Span) {}
