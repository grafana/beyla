package ebpf

import (
	"context"

	"github.com/cilium/ebpf/link"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"

	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

type instrumenter struct{}

// dummy implementations to avoid compilation errors in Darwin.
// The tracer component is only usable in Linux.
func (pt *ProcessTracer) Run(_ context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
}

func NewProcessTracer(_ ProcessTracerType, _ []Tracer) *ProcessTracer {
	return nil
}

func (pt *ProcessTracer) Init(_ *ebpfcommon.EBPFEventContext) error {
	return nil
}

func (pt *ProcessTracer) NewExecutable(_ *link.Executable, _ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) NewExecutableInstance(_ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(_ *exec.FileInfo) {}

func RunUtilityTracer(_ context.Context, _ UtilityTracer) error {
	return nil
}
