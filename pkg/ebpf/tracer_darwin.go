package ebpf

import (
	"context"

	"github.com/mariomac/pipes/pkg/node"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/ebpf/common"
)

// dummy functions and types to avoid compilation errors in Darwin. The tracer component is only usable in Linux.

func TracerProvider(ctx context.Context, cfg ebpfcommon.TracerConfig) ([]node.StartFuncCtx[[]any], error) { //nolint:all
	return nil, nil
}
