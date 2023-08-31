package ebpf

import (
	"context"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// dummy functions and types to avoid compilation errors in Darwin. The finder component is only usable in Linux.
type ProcessFinder struct {
	Cfg     *ebpfcommon.TracerConfig
	Metrics imetrics.Reporter
	CtxInfo *global.ContextInfo
}

func (pf *ProcessFinder) Start(_ context.Context) (<-chan *ProcessTracer, error) { return nil, nil }
func (pf *ProcessFinder) Close() error                                           { return nil }
