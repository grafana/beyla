package ebpf

import (
	"context"

	"github.com/mariomac/pipes/pkg/node"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/ebpf/common"
	"github.com/grafana/ebpf-autoinstrument/pkg/exec"
	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
)

// dummy functions and types to avoid compilation errors in Darwin. The tracer component is only usable in Linux.
type ProcessTracer struct {
	ELFInfo *exec.FileInfo
}

func TracerProvider(_ context.Context, _ *ProcessTracer) ([]node.StartFuncCtx[[]any], error) {
	return nil, nil
}

func FindAndInstrument(_ context.Context, _ *ebpfcommon.TracerConfig, _ imetrics.Reporter) (*ProcessTracer, error) {
	return nil, nil
}
