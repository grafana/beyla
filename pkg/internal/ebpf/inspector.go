package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/grafana/beyla/pkg/internal/ebpf/services"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/pipe"
)

func inspectLog() *slog.Logger {
	return slog.With("component", "ebpf.Inspector")
}

type Instrumentable struct {
	FileInfo *exec.FileInfo
	Offsets  *goexec.Offsets
}

type Inspector struct {
	cfg       *pipe.Config
	functions []string
	pidMap    map[int32]*exec.FileInfo
}

func NewInspector(cfg *pipe.Config, functions []string) *Inspector {
	return &Inspector{cfg: cfg, functions: functions, pidMap: map[int32]*exec.FileInfo{}}
}

func (ei *Inspector) Inspect(ctx context.Context) ([]Instrumentable, error) {
	log := inspectLog()
	elfs, err := exec.FindExecELFs(ctx, findingCriteria(ei.cfg))
	defer func() {
		for _, e := range elfs {
			e.ELF.Close()
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("looking for executable ELFs: %w", err)
	}
	// Build first a PID map so we use only the parent processes
	// in case of multiple matches
	for i := range elfs {
		ei.pidMap[elfs[i].Pid] = &elfs[i]
	}
	return out, nil
}




