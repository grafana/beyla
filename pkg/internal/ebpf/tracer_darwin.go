package ebpf

import (
	"context"

	"github.com/cilium/ebpf/link"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/request"
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

func BuildPinPath(_ *beyla.Config) string {
	return ""
}

func (pt *ProcessTracer) NewExecutable(_ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) NewExecutableInstance(_ *link.Executable, _ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(_ *exec.FileInfo) {}

func RunUtilityTracer(_ UtilityTracer, _ string, _ bool) error {
	return nil
}
