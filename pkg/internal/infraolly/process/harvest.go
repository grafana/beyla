// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package process provides all the tools and functionality for sampling processes. It is divided in three main
// components:
// - Status: provides OS-level information of a process at a given spot
// - Harvester: fetches and creates actual Process Status from system
// - Collector: uses input from the application pipeline to fetch information for all the processes from
//   the instrumented applications, and forwards it to the next stage of the Process' pipeline.
package process

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/v3/process"
)

func hlog() *slog.Logger {
	return slog.With("component", "process.Harvester")
}

var errProcessWithoutRSS = fmt.Errorf("process with zero rss")

// Harvester manages sampling for individual processes. It is used by the Process Collector to get information about the
// existing processes.
type Harvester interface {
	// Pids return the IDs of all the processes that are currently running
	Pids() ([]int32, error)
	// Do performs the actual harvesting operation, returning a process status containing all the metrics data
	Do(pid int32) (*Status, error)
}

type RunMode string

const (
	RunModeRoot         = "root"
	RunModePrivileged   = "privileged"
	RunModeUnprivileged = "unprivileged"
)

type Config struct {
	RunMode              RunMode
	DisableZeroRSSFilter bool
	FullCommandLine      bool

	ProcFSRoot string
	Rate       time.Duration
}

func newHarvester(cfg Config, cache *simplelru.LRU[int32, *cacheEntry]) *linuxHarvester {
	// If not config, assuming root mode as default
	privileged := cfg.RunMode == RunModeRoot || cfg.RunMode == RunModePrivileged
	disableZeroRSSFilter := cfg.DisableZeroRSSFilter
	stripCommandLine := !cfg.FullCommandLine

	return &linuxHarvester{
		procFSRoot:           cfg.ProcFSRoot,
		privileged:           privileged,
		disableZeroRSSFilter: disableZeroRSSFilter,
		stripCommandLine:     stripCommandLine,
		cache:                cache,
		log:                  hlog(),
	}
}

// linuxHarvester is a Harvester implementation that uses various linux sources and manages process caches
type linuxHarvester struct {
	procFSRoot           string
	privileged           bool
	disableZeroRSSFilter bool
	stripCommandLine     bool
	cache                *simplelru.LRU[int32, *cacheEntry]
	log                  *slog.Logger
}

var _ Harvester = (*linuxHarvester)(nil) // static interface assertion

// Pids returns a slice of process IDs that are running now
func (*linuxHarvester) Pids() ([]int32, error) {
	return process.Pids()
}

// Do returns a status of a process whose PID is passed as argument. The 'elapsedSeconds' argument represents the
// time since this process was statusd for the last time. If the process has been statusd for the first time, this value
// will be ignored
func (ps *linuxHarvester) Do(pid int32) (*Status, error) {
	// Reuses process information that does not vary
	cached, hasCachedEntry := ps.cache.Get(pid)

	// If cached is nil, the linux process will be created from fresh data
	if !hasCachedEntry {
		cached = &cacheEntry{}
	}
	var err error
	cached.process, err = getLinuxProcess(ps.procFSRoot, pid, cached.process, ps.privileged)
	if err != nil {
		return nil, errors.Wrap(err, "can't create process")
	}

	// We don't need to report processes which are not using memory. This filters out certain kernel processes.
	if !ps.disableZeroRSSFilter && cached.process.VMRSS() == 0 {
		return nil, errProcessWithoutRSS
	}

	// Creates a fresh process status and populates it with the metrics data
	status := NewStatus(pid)

	if err := ps.populateStaticData(status, cached.process); err != nil {
		return nil, errors.Wrap(err, "can't populate static attributes")
	}

	// As soon as we have successfully stored the static (reusable) values, we can cache the entry
	if !hasCachedEntry {
		ps.cache.Add(pid, cached)
	}

	if err := ps.populateGauges(status, cached.process); err != nil {
		return nil, errors.Wrap(err, "can't fetch gauge data")
	}

	if err := ps.populateIOCounters(status, cached.process); err != nil {
		return nil, errors.Wrap(err, "can't fetch deltas")
	}

	cached.last = status

	return status, nil
}

// populateStaticData populates the status with the process data won't vary during the process life cycle
func (ps *linuxHarvester) populateStaticData(status *Status, process *linuxProcess) error {
	var err error
	status.CmdLine, err = process.CmdLine(!ps.stripCommandLine)
	if err != nil {
		return errors.Wrap(err, "acquiring command line")
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
func (ps *linuxHarvester) populateGauges(status *Status, process *linuxProcess) error {
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
func (ps *linuxHarvester) populateIOCounters(status *Status, source *linuxProcess) error {
	ioCounters, err := source.IOCounters()
	if err != nil {
		return err
	}
	status.IOReadCount = ioCounters.ReadCount
	status.IOWriteCount = ioCounters.WriteCount
	status.IOReadBytes = ioCounters.ReadBytes
	status.IOWriteBytes = ioCounters.WriteBytes
	return nil
}
