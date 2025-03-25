package ebpf

import (
	"context"

	"github.com/cilium/ebpf/link"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

type instrumenter struct {
}

// dummy implementations to avoid compilation errors in Darwin.
// The tracer component is only usable in Linux.
func (pt *ProcessTracer) Run(_ context.Context, _ chan<- []request.Span) {}

func NewProcessTracer(_ *beyla.Config, _ ProcessTracerType, _ []Tracer) *ProcessTracer {
	return nil
}

func (pt *ProcessTracer) Init() error {
	return nil
}

func (pt *ProcessTracer) NewExecutable(_ *link.Executable, _ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) NewExecutableInstance(_ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(_ *exec.FileInfo) {}

func RunUtilityTracer(_ UtilityTracer) error {
	return nil
}
