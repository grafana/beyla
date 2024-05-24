// Copyright New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
)

// Process it's an interface to abstract gopsutil process so we can mock it and test not coupling to infra
type Process interface {
	Username() (string, error)
	Name() (string, error)
	Cmdline() (string, error)
	ProcessId() int32
	Parent() (Process, error)
	NumThreads() (int32, error)
	Status() ([]string, error)
	MemoryInfo() (*process.MemoryInfoStat, error)
	CPUPercent() (float64, error)
	Times() (*cpu.TimesStat, error)
}

// ProcessWrapper is necessary to implement the interface as gopsutil process is not exporting Pid()
type ProcessWrapper struct {
	*process.Process
}

// ProcessId returns the Pid of the process
func (p *ProcessWrapper) ProcessId() int32 {
	return p.Process.Pid
}

// Parent return the process' parent
func (p *ProcessWrapper) Parent() (Process, error) {
	par, err := p.Process.Parent()
	if err != nil {
		return &ProcessWrapper{}, err
	}
	return &ProcessWrapper{par}, nil
}
