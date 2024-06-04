// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package process provides all the tools and functionality for sampling processes. It is divided in three main
// components:
//   - Status: provides OS-level information of a process at a given spot
//   - Harvester: fetches and creates actual Process Status from system
//   - Collector: uses input from the application pipeline to fetch information for all the processes from
//     the instrumented applications, and forwards it to the next stage of the Process' pipeline.
package process

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"github.com/grafana/beyla/pkg/internal/svc"
)

func hlog() *slog.Logger {
	return slog.With("component", "process.Harvester")
}

type RunMode string

const (
	RunModePrivileged   = "privileged"
	RunModeUnprivileged = "unprivileged"
)

// Harvester fetches processes' information from Linux
type Harvester struct {
	// allows overriding the /proc filesystem location via HOST_PROC env var
	procFSRoot string
	privileged bool
	cache      *simplelru.LRU[int32, *linuxProcess]
	log        *slog.Logger
}

func newHarvester(cfg *CollectConfig, cache *simplelru.LRU[int32, *linuxProcess]) *Harvester {
	// we need to use the same method to override HOST_PROC that is used by gopsutil library
	hostProc, ok := os.LookupEnv("HOST_PROC")
	if !ok {
		hostProc = "/proc"
	}

	return &Harvester{
		procFSRoot: hostProc,
		privileged: cfg.RunMode == RunModePrivileged,
		cache:      cache,
		log:        hlog(),
	}
}

// Harvest returns a status of a process whose PID is passed as argument. The 'elapsedSeconds' argument represents the
// time since this process was statusd for the last time. If the process has been statusd for the first time, this value
// will be ignored
func (ps *Harvester) Harvest(svcID *svc.ID) (*Status, error) {
	pid := svcID.ProcPID
	ps.log.Debug("harvesting pid", "pid", pid)
	// Reuses process information that does not vary
	cached, hasCachedEntry := ps.cache.Get(pid)

	var err error
	// If cached is nil, the linux process will be created from fresh data
	cached, err = getLinuxProcess(cached, ps.procFSRoot, pid, ps.privileged)
	if err != nil {
		return nil, fmt.Errorf("can't create process: %w", err)
	}

	// Creates a fresh process status and populates it with the metrics data
	status := NewStatus(pid, svcID)

	if err := ps.populateStaticData(status, cached); err != nil {
		return nil, fmt.Errorf("can't populate static attributes: %w", err)
	}

	// As soon as we have successfully stored the static (reusable) values, we can cache the entry
	if !hasCachedEntry {
		ps.cache.Add(pid, cached)
	}

	if err := ps.populateGauges(status, cached); err != nil {
		return nil, fmt.Errorf("can't fetch gauge data: %w", err)
	}

	if err := ps.populateIOCounters(status, cached); err != nil {
		return nil, fmt.Errorf("can't fetch deltas: %w", err)
	}

	return status, nil
}

// populateStaticData populates the status with the process data won't vary during the process life cycle
func (ps *Harvester) populateStaticData(status *Status, process *linuxProcess) error {
	var err error
	status.CommandLine, err = process.CmdLine()
	if err != nil {
		return fmt.Errorf("acquiring command line: %w", err)
	}

	status.ProcessID = process.Pid()

	status.User, err = process.Username()
	if err != nil {
		ps.log.Debug("can't get username for process", "pid", status.ProcessID, "error", err)
	}

	status.Command = process.Command()
	status.ParentProcessID = process.Ppid()

	return nil
}

// populateGauges populates the status with gauge data that represents the process state at a given point
func (ps *Harvester) populateGauges(status *Status, process *linuxProcess) error {
	var err error

	cpuTimes, err := process.CPUTimes()
	if err != nil {
		return err
	}
	status.CPUPercent = cpuTimes.Percent

	totalCPU := cpuTimes.User + cpuTimes.System

	if totalCPU > 0 {
		status.CPUUserPercent = (cpuTimes.User / totalCPU) * status.CPUPercent
		status.CPUSystemPercent = (cpuTimes.System / totalCPU) * status.CPUPercent
	} else {
		status.CPUUserPercent = 0
		status.CPUSystemPercent = 0
	}

	if ps.privileged {
		status.FdCount, err = process.NumFDs()
		if err != nil {
			return err
		}
	}

	// Extra status data
	status.Status = process.Status()
	status.ThreadCount = process.NumThreads()
	status.MemoryVMSBytes = process.VMSize()
	status.MemoryRSSBytes = process.VMRSS()

	return nil
}

// populateIOCounters fills the status with the IO counters data. For the "X per second" metrics, it requires the
// last process status for comparative purposes
func (ps *Harvester) populateIOCounters(status *Status, source *linuxProcess) error {
	ioCounters, err := source.IOCounters()
	if err != nil {
		return err
	}
	if ioCounters != nil {
		status.IOReadCount = ioCounters.ReadCount
		status.IOWriteCount = ioCounters.WriteCount
		status.IOReadBytes = ioCounters.ReadBytes
		status.IOWriteBytes = ioCounters.WriteBytes
	}
	return nil
}
