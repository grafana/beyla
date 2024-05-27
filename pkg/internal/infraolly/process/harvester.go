// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package process provides all the tools and functionality for sampling processes. It is divided in three main
// components:
// - Snapshot: provides OS-level information of a process at a given spot
// - Harvester: manages process Snapshots to create actual Process Samples with the actual metrics.
// - Sampler: uses the harvester to coordinate the creation of the Process Samples dataset, as being reported to NR
package process

import (
	"fmt"
	"log/slog"
)

func mplog() *slog.Logger {
	return slog.With("component", "process.Sampler")
}

var errProcessWithoutRSS = fmt.Errorf("process with zero rss")

// Harvester manages sampling for individual processes. It is used by the Process Sampler to get information about the
// existing processes.
type Harvester interface {
	// Pids return the IDs of all the processes that are currently running
	Pids() ([]int32, error)
	// Do performs the actual harvesting operation, returning a process sample containing all the metrics data
	Do(pid int32) (*Sample, error)
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
	FullCommandLine     bool
}
