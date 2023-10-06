// Package goexec provides the utilities to analyse the executable code
package exec

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/grafana/beyla/pkg/internal/ebpf/services"
	"github.com/grafana/beyla/pkg/internal/svc"
)

// TODO: user-configurable
const retryTicker = 3 * time.Second

type ProcessReader interface {
	io.ReaderAt
	io.Closer
}


func log() *slog.Logger {
	return slog.With("component", "exec")
}


// findExecELF operation blocks until the executable is available.
// TODO: check that all the existing instances of the excutable are instrumented, even when it is offloaded from memory
func FindExecELFs(ctx context.Context, criteria services.DefinitionCriteria) ([]FileInfo, error) {
	var fileInfos []FileInfo
	log := log()

	log.Debug("searching for process executables")
	processMatches, err := findProcesses(criteria)
	if len(processMatches) == 0 || err != nil {
		select {
		case <-ctx.Done():
			log.Debug("context was cancelled before finding the process. Exiting")
			return []FileInfo{}, errors.New("process not found")
		default:
			log.Debug("no processes found. Will retry", "retryAfter", retryTicker.String())
			time.Sleep(retryTicker)
		}
		continue
	}
	for _, m := range processMatches {
		p := m.Process
		fileInfos = append(fileInfos, file)
	}

	return fileInfos, nil
}
