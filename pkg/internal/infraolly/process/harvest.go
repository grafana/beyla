// Copyright 2020 New Relic Corporation
// Copyright 2024 Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This implementation was inspired by the code in https://github.com/newrelic/infrastructure-agent

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
	"path"
	"runtime"
	"strconv"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/shirou/gopsutil/v3/process"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
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
func (ps *Harvester) Harvest(svcID *svc.Attrs) (*Status, error) {
	pid := svcID.ProcPID
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

	ps.populateNetworkInfo(status, cached)

	// current stats will be used in the next iteration to calculate some delta values
	cached.prevStats = cached.stats

	return status, nil
}

// populateStaticData populates the status with the process data won't vary during the process life cycle
func (ps *Harvester) populateStaticData(status *Status, process *linuxProcess) error {
	process.fetchCommandInfo()
	status.ID.Command = process.stats.command
	status.ID.CommandArgs = process.commandArgs
	status.ID.CommandLine = process.commandLine
	status.ID.ExecPath = process.execPath
	status.ID.ExecName = process.execName

	status.ID.ProcessID = process.Pid()

	var err error
	if status.ID.User, err = process.Username(); err != nil {
		ps.log.Debug("can't get username for process", "pid", status.ID.ProcessID, "error", err)
	}

	status.ID.ParentProcessID = process.stats.ppid

	return nil
}

// populateGauges populates the status with gauge data that represents the process state at a given point
func (ps *Harvester) populateGauges(status *Status, process *linuxProcess) error {
	var err error

	// Calculate CPU metrics from current and previous user/system/wait time
	var zero CPUInfo
	// we only calculate CPU deltas and utilization time from the second sample onwards
	if process.prevStats.cpu != zero {
		status.CPUTimeSystemDelta = process.stats.cpu.SystemTime - process.prevStats.cpu.SystemTime
		status.CPUTimeUserDelta = process.stats.cpu.UserTime - process.prevStats.cpu.UserTime
		status.CPUTimeWaitDelta = process.stats.cpu.WaitTime - process.prevStats.cpu.WaitTime

		delta := process.measureTime.Sub(process.previousMeasureTime).Seconds() * float64(runtime.NumCPU())
		status.CPUUtilisationSystem = (process.stats.cpu.SystemTime - process.prevStats.cpu.SystemTime) / delta
		status.CPUUtilisationUser = (process.stats.cpu.UserTime - process.prevStats.cpu.UserTime) / delta
		status.CPUUtilisationWait = (process.stats.cpu.WaitTime - process.prevStats.cpu.WaitTime) / delta
	}

	if ps.privileged {
		status.FdCount, err = process.NumFDs()
		if err != nil {
			return err
		}
	}

	// Extra status data
	status.Status = process.stats.state
	status.ThreadCount = process.stats.numThreads
	status.MemoryVMSBytes = process.stats.vmSize
	status.MemoryVMSBytesDelta = process.stats.vmSize - process.prevStats.vmSize
	status.MemoryRSSBytes = process.stats.vmRSS
	status.MemoryRSSBytesDelta = process.stats.vmRSS - process.prevStats.vmRSS

	return nil
}

// populateIOCounters fills the status with the IO counters data. For the delta metrics, it requires the
// last process status for comparative purposes
func (ps *Harvester) populateIOCounters(status *Status, source *linuxProcess) error {
	previous := source.previousIOCounters
	if previous == nil {
		previous = &process.IOCountersStat{}
	}
	ioCounters, err := source.IOCounters()
	if err != nil {
		return err
	}
	source.previousIOCounters = ioCounters
	if ioCounters != nil {
		status.IOReadCount = ioCounters.ReadCount
		status.IOWriteCount = ioCounters.WriteCount
		status.IOReadBytesDelta = ioCounters.ReadBytes - previous.ReadBytes
		status.IOWriteBytesDelta = ioCounters.WriteBytes - previous.WriteBytes
	}
	return nil
}

func (ps *Harvester) populateNetworkInfo(status *Status, source *linuxProcess) {
	statPath := path.Join(ps.procFSRoot, strconv.Itoa(int(source.pid)), "net", "dev")
	content, err := os.ReadFile(statPath)
	if err != nil {
		ps.log.Debug("can't read net dev file", "path", statPath, "error", err)
		return
	}
	rx, tx := parseProcNetDev(content)
	// removing a row in the /proc/<pid>/net/dev table could cause a negative delta
	// and crashing the counters in the instrumentation libraries
	if rx <= source.previousNetRx || tx <= source.previousNetTx {
		status.NetRcvBytesDelta = 0
		status.NetTxBytesDelta = 0
	} else {
		status.NetRcvBytesDelta = rx - source.previousNetRx
		status.NetTxBytesDelta = tx - source.previousNetTx
	}
	source.previousNetRx = rx
	source.previousNetTx = tx
}
