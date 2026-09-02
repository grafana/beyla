// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"fmt"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// StartTime returns the process start time in clock ticks since boot, as
// reported by /proc/<pid>/stat. Together with the PID it identifies a process
// unambiguously, so callers can detect PID reuse.
func StartTime(pid app.PID) (uint64, error) {
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return 0, fmt.Errorf("opening process %d: %w", pid, err)
	}

	stat, err := proc.Stat()
	if err != nil {
		return 0, fmt.Errorf("reading stat of process %d: %w", pid, err)
	}

	return stat.Starttime, nil
}
