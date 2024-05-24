// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package process

import (
	"github.com/shirou/gopsutil/v3/process"
)

// CPUInfo represents CPU usage statistics at a given point
type CPUInfo struct {
	// Percent is the total CPU usage percent
	Percent float64
	// User is the CPU user time
	User float64
	// System is the CPU system time
	System float64
}

// Snapshot represents the status of a process at a given time. Instances of Snapshot must not be
// reused for different samples
type Snapshot interface {
	// Pid returns the Process ID
	Pid() int32
	// Ppid returns the Parent Process ID
	Ppid() int32
	// Status returns the state of the process: R (running or runnable), D (uninterruptible sleep), S (interruptible
	// sleep), Z (defunct/zombie) or T (stopped)
	Status() string
	// Command returns the process Command name
	Command() string
	// CmdLine returns the process invoking command line, with or without arguments
	CmdLine(withArgs bool) (string, error)
	// Username returns the name of the process owner user
	Username() (string, error)
	// CPUTimes returns the CPU consumption percentages for the process
	CPUTimes() (CPUInfo, error)
	// IOCounters returns the I/O statistics for the process
	IOCounters() (*process.IOCountersStat, error)
	// NumThreads returns the number of threads that are being used by the process
	NumThreads() int32
	// NumFDs returns the number of File Descriptors that are open by the process
	NumFDs() (int32, error)
	// VmRSS returns the Resident Set Size (memory in RAM) of the process
	VmRSS() int64
	// VmSize returns the total memory of the process (RSS + virtual memory)
	VmSize() int64
}
