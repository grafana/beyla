// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin
// +build linux darwin

// Package process provides all the tools and functionality for sampling processes. It is divided in three main
// components:
// - Snapshot: provides OS-level information of a process at a given spot
// - Harvester: manages process Snapshots to create actual Process Samples with the actual metrics.
// - Sampler: uses the harvester to coordinate the creation of the Process Samples dataset, as being reported to NR
package process

import (
	"fmt"

	"github.com/newrelic/infrastructure-agent/pkg/log"
	"github.com/newrelic/infrastructure-agent/pkg/metrics/types"
)

var mplog = log.WithComponent("ProcessSampler")

var errProcessWithoutRSS = fmt.Errorf("process with zero rss")

// Harvester manages sampling for individual processes. It is used by the Process Sampler to get information about the
// existing processes.
type Harvester interface {
	// Pids return the IDs of all the processes that are currently running
	Pids() ([]int32, error)
	// Do performs the actual harvesting operation, returning a process sample containing all the metrics data
	// for the last elapsedSeconds
	Do(pid int32, elapsedSeconds float64) (*Sample, error)
}
