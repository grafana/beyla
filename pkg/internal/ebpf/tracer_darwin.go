package ebpf

import (
	"context"

	"github.com/cilium/ebpf/link"

	"github.com/grafana/beyla/pkg/internal/request"
)

// dummy implementations to avoid compilation errors in Darwin.
// The tracer component is only usable in Linux.
func (pt *ProcessTracer) Run(_ context.Context, _ chan<- []request.Span) {}

func (pt *ProcessTracer) Init() error {
	return nil
}

func (pt *ProcessTracer) NewExecutableForTracer(exe *link.Executable, ie *Instrumentable) error {
	return nil
}

func RunUtilityTracer(_ UtilityTracer, _ string) error {
	return nil
}
