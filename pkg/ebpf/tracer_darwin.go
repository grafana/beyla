package ebpf

import (
	"context"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/ebpf/common"
	"github.com/mariomac/pipes/pkg/node"
)

// dummy functions and types to avoid compilation errors in Darwin. The tracer component is only usable in Linux.

func TracerProvider(ctx context.Context, cfg ebpfcommon.TracerConfig) ([]node.StartFuncCtx[[]any], error) { //nolint:all
	return nil, nil
}
