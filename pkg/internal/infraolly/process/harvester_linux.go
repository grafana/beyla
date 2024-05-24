// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Package process provides all the tools and functionality for sampling processes. It is divided in three main
// components:
// - Snapshot: provides OS-level information of a process at a given spot
// - Harvester: manages process Snapshots to create actual Process Samples with the actual metrics.
// - Sampler: uses the harvester to coordinate the creation of the Process Samples dataset, as being reported to NR
package process

import (
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/newrelic/infrastructure-agent/internal/agent"
	"github.com/newrelic/infrastructure-agent/pkg/config"
	"github.com/newrelic/infrastructure-agent/pkg/metrics"
	"github.com/newrelic/infrastructure-agent/pkg/metrics/acquire"
	"github.com/newrelic/infrastructure-agent/pkg/metrics/types"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/sirupsen/logrus"
)

func newHarvester(ctx agent.AgentContext, cache *simplelru.LRU[int32, *cacheEntry]) *linuxHarvester {
	cfg := ctx.Config()
	// If not config, assuming root mode as default
	privileged := cfg == nil || cfg.RunMode == config.ModeRoot || cfg.RunMode == config.ModePrivileged
	disableZeroRSSFilter := cfg != nil && cfg.DisableZeroRSSFilter
	stripCommandLine := (cfg != nil && cfg.StripCommandLine) || (cfg == nil && config.DefaultStripCommandLine)

	return &linuxHarvester{
		privileged:           privileged,
		disableZeroRSSFilter: disableZeroRSSFilter,
		stripCommandLine:     stripCommandLine,
		serviceForPid:        ctx.GetServiceForPid,
		cache:                cache,
	}
}

// linuxHarvester is a Harvester implementation that uses various linux sources and manages process caches
type linuxHarvester struct {
	privileged           bool
	disableZeroRSSFilter bool
	stripCommandLine     bool
	cache                *cache
	serviceForPid        func(int) (string, bool)
}

var _ Harvester = (*linuxHarvester)(nil) // static interface assertion

// Pids returns a slice of process IDs that are running now
func (*linuxHarvester) Pids() ([]int32, error) {
	return process.Pids()
}

// Returns a sample of a process whose PID is passed as argument. The 'elapsedSeconds' argument represents the
// time since this process was sampled for the last time. If the process has been sampled for the first time, this value
// will be ignored
func (ps *linuxHarvester) Do(pid int32, elapsedSeconds float64) (*Sample, error) {
	// Reuses process information that does not vary
	cached, hasCachedSample := ps.cache.Get(pid)

	// If cached is nil, the linux process will be created from fresh data
	if !hasCachedSample {
		cached = &cacheEntry{}
	}
	var err error
	cached.process, err = getLinuxProcess(pid, cached.process, ps.privileged)
	if err != nil {
		return nil, errors.Wrap(err, "can't create process")
	}

	// We don't need to report processes which are not using memory. This filters out certain kernel processes.
	if !ps.disableZeroRSSFilter && cached.process.VmRSS() == 0 {
		return nil, errProcessWithoutRSS
	}

	// Creates a fresh process sample and populates it with the metrics data
	sample := metrics.NewProcessSample(pid)

	if err := ps.populateStaticData(sample, cached.process); err != nil {
		return nil, errors.Wrap(err, "can't populate static attributes")
	}

	// As soon as we have successfully stored the static (reusable) values, we can cache the entry
	if !hasCachedSample {
		ps.cache.Add(pid, cached)
	}

	if err := ps.populateGauges(sample, cached.process); err != nil {
		return nil, errors.Wrap(err, "can't fetch gauge data")
	}

	if err := ps.populateIOCounters(sample, cached.lastSample, cached.process, elapsedSeconds); err != nil {
		return nil, errors.Wrap(err, "can't fetch deltas")
	}

	// This must happen every time, even if we already had a cached sample for the process, because
	// the available process name metadata may have changed underneath us (if we pick up a new
	// service/PID association, etc)
	sample.ProcessDisplayName = ps.determineProcessDisplayName(sample)

	sample.Type("ProcessSample")
	cached.lastSample = sample

	return sample, nil
}

// populateStaticData populates the sample with the process data won't vary during the process life cycle
func (ps *linuxHarvester) populateStaticData(sample *Sample, process Snapshot) error {
	var err error
	sample.CmdLine, err = process.CmdLine(!ps.stripCommandLine)
	if err != nil {
		return errors.Wrap(err, "acquiring command line")
	}

	sample.ProcessID = process.Pid()

	sample.User, err = process.Username()
	if err != nil {
		mplog.WithError(err).WithField("processID", sample.ProcessID).Debug("Can't get Username for process.")
	}

	sample.CommandName = process.Command()
	sample.ParentProcessID = process.Ppid()

	return nil
}

// populateGauges populates the sample with gauge data that represents the process state at a given point
func (ps *linuxHarvester) populateGauges(sample *Sample, process Snapshot) error {
	var err error

	cpuTimes, err := process.CPUTimes()
	if err != nil {
		return err
	}
	sample.CPUPercent = cpuTimes.Percent

	totalCPU := cpuTimes.User + cpuTimes.System

	if totalCPU > 0 {
		sample.CPUUserPercent = (cpuTimes.User / totalCPU) * sample.CPUPercent
		sample.CPUSystemPercent = (cpuTimes.System / totalCPU) * sample.CPUPercent
	} else {
		sample.CPUUserPercent = 0
		sample.CPUSystemPercent = 0
	}

	if ps.privileged {
		fds, err := process.NumFDs()
		if err != nil {
			return err
		}
		if fds >= 0 {
			sample.FdCount = &fds
		}
	}

	// Extra status data
	sample.Status = process.Status()
	sample.ThreadCount = process.NumThreads()
	sample.MemoryVMSBytes = process.VmSize()
	sample.MemoryRSSBytes = process.VmRSS()

	return nil
}

// populateIOCounters fills the sample with the IO counters data. For the "X per second" metrics, it requires the
// last process sample for comparative purposes
func (ps *linuxHarvester) populateIOCounters(sample, lastSample *Sample, source Snapshot, elapsedSeconds float64) error {
	ioCounters, err := source.IOCounters()
	if err != nil {
		return err
	}
	if ioCounters != nil {
		// Delta
		if lastSample != nil && lastSample.LastIOCounters != nil {
			lastCounters := lastSample.LastIOCounters

			mplog.WithField(config.TracesFieldName, config.FeatureTrace).Tracef("ReadCount: %d, WriteCount: %d, ReadBytes: %d, WriteBytes: %d", ioCounters.ReadCount, ioCounters.WriteCount, ioCounters.ReadBytes, ioCounters.WriteBytes)
			ioReadCountPerSecond := acquire.CalculateSafeDelta(ioCounters.ReadCount, lastCounters.ReadCount, elapsedSeconds)
			ioWriteCountPerSecond := acquire.CalculateSafeDelta(ioCounters.WriteCount, lastCounters.WriteCount, elapsedSeconds)
			ioReadBytesPerSecond := acquire.CalculateSafeDelta(ioCounters.ReadBytes, lastCounters.ReadBytes, elapsedSeconds)
			ioWriteBytesPerSecond := acquire.CalculateSafeDelta(ioCounters.WriteBytes, lastCounters.WriteBytes, elapsedSeconds)

			sample.IOReadCountPerSecond = &ioReadCountPerSecond
			sample.IOWriteCountPerSecond = &ioWriteCountPerSecond
			sample.IOReadBytesPerSecond = &ioReadBytesPerSecond
			sample.IOWriteBytesPerSecond = &ioWriteBytesPerSecond
		}

		// Cumulative
		sample.IOTotalReadCount = &ioCounters.ReadCount
		sample.IOTotalWriteCount = &ioCounters.WriteCount
		sample.IOTotalReadBytes = &ioCounters.ReadBytes
		sample.IOTotalWriteBytes = &ioCounters.WriteBytes

		sample.LastIOCounters = ioCounters
	}
	return nil
}

// determineProcessDisplayName generates a human-friendly name for this process. By default, we use the command name.
// If we know of a service for this pid, that'll be the name.
func (ps *linuxHarvester) determineProcessDisplayName(sample *Sample) string {
	displayName := sample.CommandName
	if serviceName, ok := ps.serviceForPid(int(sample.ProcessID)); ok && len(serviceName) > 0 {
		mplog.WithFieldsF(func() logrus.Fields {
			return logrus.Fields{"serviceName": serviceName, "displayName": displayName, "ProcessID": sample.ProcessID}
		}).Debug("Using service name as display name.")
		displayName = serviceName
	}

	return displayName
}
