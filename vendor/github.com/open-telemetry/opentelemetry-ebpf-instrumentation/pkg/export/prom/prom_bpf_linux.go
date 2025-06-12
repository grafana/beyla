package prom

import (
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func (bc *BPFCollector) enableBPFStatsRuntime() {
	_, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		bc.log.Error("failed to enable runtime stats", "error", err)
	}
}
