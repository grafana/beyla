//go:build !linux

package surveywatcher

import (
	"context"
	"errors"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
)

func Start(context.Context, *obi.Config, *ebpfcommon.EBPFEventContext) (*State, error) {
	return nil, errors.New("survey socket_apps requires Linux")
}
