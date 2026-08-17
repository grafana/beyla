// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

var enableStats = ebpf.EnableStats

func (bc *BPFCollector) enableBPFStatsRuntime() func() {
	stats, err := enableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		bc.log.Error("failed to enable runtime stats", "error", err)
		return func() {}
	}

	return func() {
		if err := stats.Close(); err != nil {
			bc.log.Error("failed to close runtime stats", "error", err)
		}
	}
}
