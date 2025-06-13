//go:build !linux

package prom

func (bc *BPFCollector) enableBPFStatsRuntime() {}
