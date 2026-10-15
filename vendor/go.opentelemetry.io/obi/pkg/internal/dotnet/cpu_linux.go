// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"fmt"

	"github.com/tklauser/go-sysconf"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func readProcessCPUTimes(process *procs.ProcessHandle) (float64, float64, error) {
	user, system, err := process.CPUTimeTicks()
	if err != nil {
		return 0, 0, fmt.Errorf("reading process CPU ticks: %w", err)
	}
	ticksPerSecond, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	if err != nil {
		return 0, 0, fmt.Errorf("reading CPU clock tick rate: %w", err)
	}
	if ticksPerSecond <= 0 {
		return 0, 0, fmt.Errorf("invalid CPU clock tick rate: %d", ticksPerSecond)
	}
	return float64(user) / float64(ticksPerSecond), float64(system) / float64(ticksPerSecond), nil
}
