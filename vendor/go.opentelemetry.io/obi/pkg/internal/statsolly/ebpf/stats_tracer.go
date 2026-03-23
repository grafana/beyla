// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type StatsTCPRtt StatsTcpRttT

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type tcp_rtt_t -target amd64,arm64 Stats ../../../../bpf/statsolly/k_tcp.c -- -I../../../../bpf

type StatsFetcher struct {
	log         *slog.Logger
	statsEvents *ebpf.Map
	closables   []io.Closer
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

func NewStatsFetcher() (*StatsFetcher, error) {
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := StatsObjects{}
	spec, err := LoadStats()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// Debug events map is unsupported due to pinning
	spec.Maps["debug_events"] = &ebpf.MapSpec{
		Name:       "dummy_map",
		Type:       ebpf.RingBuf,
		Pinning:    ebpf.PinNone,
		MaxEntries: uint32(os.Getpagesize()),
	}

	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	ktc, err := link.Kprobe("tcp_close", objects.ObiKprobeTcpCloseSrtt, nil)
	if err != nil {
		tlog.Error("opening %s: %s", "tcp_close", err)
		return nil, fmt.Errorf("opening kprobe: %w", err)
	}

	var closables []io.Closer
	return &StatsFetcher{
		log:         tlog,
		statsEvents: objects.StatsEvents,
		closables:   append(closables, ktc),
	}, nil
}

// Close any resources that are taken
func (m *StatsFetcher) Close() error {
	m.log.Debug("unregistering eBPF objects")

	var errs []error
	for _, c := range m.closables {
		if c != nil {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}

// StatsEventsMap returns the ring buffer map for stats events.
// The caller (ForwardRingbuf) is responsible for creating and closing the reader.
func (m *StatsFetcher) StatsEventsMap() *ebpf.Map {
	return m.statsEvents
}
