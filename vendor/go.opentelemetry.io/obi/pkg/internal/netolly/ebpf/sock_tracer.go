// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Copyright Grafana Labs
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

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gavv/monotime"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	convenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type flow_metrics_t -type flow_id_t -type flow_record_t -type packet_count_t -target amd64,arm64 NetSk ../../../../bpf/netolly/flows_sock.c -- -I../../../../bpf

// SockFlowFetcher reads and forwards the Flows from the eBPF kernel space with a socket filter implementation.
// It provides access both to flows that are aggregated in the kernel space (via PerfCPU hashmap)
// and to flows that are forwarded by the kernel via ringbuffer because could not be aggregated
// in the map
type SockFlowFetcher struct {
	log           *slog.Logger
	objectsMu     sync.Mutex
	objects       *NetSkObjects
	ringbufReader *ringbuf.Reader
	flowMapReader flowMapReader
}

func NewSockFlowFetcher(
	sampling, cacheMaxSize int,
	portGuessPolicy flowdef.PortGuessPolicy,
	cfg *config.EBPFTracer,
) (*SockFlowFetcher, error) {
	startTime := uint64(monotime.Now())
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := NetSkObjects{}
	spec, err := LoadNetSk()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// Resize aggregated flows and flow directions maps according to user-provided configuration
	spec.Maps[aggregatedFlowsMap].MaxEntries = uint32(cacheMaxSize)
	spec.Maps[flowDirectionsMap].MaxEntries = uint32(cacheMaxSize)
	spec.Maps[connInitiatorsMap].MaxEntries = uint32(cacheMaxSize)

	convenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)

	traceMsgs := 0
	if tlog.Enabled(context.TODO(), slog.LevelDebug) {
		traceMsgs = 1
	}
	// numeric values defined in flows_common.h
	portGuessing := uint8(0)
	if portGuessPolicy == flowdef.PortGuessOrdinal {
		portGuessing = 1
	}
	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	if err := convenience.LoadSpec(spec, &objects, map[string]any{
		constSampling:      uint32(sampling),
		constTraceMessages: uint8(traceMsgs),
		constPortGuessing:  portGuessing,
		gBpfDebug:          cfg.BpfDebug,
	}, sharedMaps, &mu, ""); err != nil {
		printVerifierErrorInfo(err)
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err == nil {
		ssoErr := syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, objects.ObiSocketFilter.FD())
		if ssoErr != nil {
			return nil, fmt.Errorf("loading and assigning BPF objects: %w", ssoErr)
		}
	} else {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	// read events from socket filter ringbuffer
	flows, err := ringbuf.NewReader(objects.DirectFlows)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}
	return &SockFlowFetcher{
		log:           tlog,
		objects:       &objects,
		ringbufReader: flows,
		flowMapReader: chooseMapReader(cfg.ForceBPFMapReader, objects.AggregatedFlows, cacheMaxSize, startTime),
	}, nil
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

// LookupPacketStats returns the internal BPF accounting of how many
// flow packets are accounted in the namespace and how many are ignored in the
// BPF space due to internal map collisions.
// Callers use it to report map-collision drops.
func (m *SockFlowFetcher) LookupPacketStats() (NetPacketCount, error) {
	m.objectsMu.Lock()
	defer m.objectsMu.Unlock()
	if m.objects == nil {
		return NetPacketCount{}, ErrTracerTerminated
	}
	return lookupPacketStats(m.objects.FlowPacketStats)
}

func (m *SockFlowFetcher) DebugEventsMap() *ebpf.Map {
	return m.objects.DebugEvents
}

// Close any resources that are taken up by the socket filter, the filter itself and some maps.
func (m *SockFlowFetcher) Close() error {
	m.log.Debug("unregistering eBPF objects")

	var errs []error
	// m.ringbufReader.Read is a blocking operation, so we need to close the ring buffer
	// from another goroutine to avoid the system not being able to exit if there
	// isn't traffic in a given interface
	if m.ringbufReader != nil {
		if err := m.ringbufReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	m.objectsMu.Lock()
	obj := m.objects
	m.objects = nil
	m.objectsMu.Unlock()

	if obj != nil {
		if err := obj.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *SockFlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}

func (m *SockFlowFetcher) LookupAndDeleteMap() map[NetFlowId]*NetFlowMetrics {
	flows, err := m.flowMapReader.lookupAndDeleteMap()
	if err != nil {
		m.log.Error("failed to read flows from eBPF map", "error", err)
	}
	return flows
}

func isLittleEndian() bool {
	var a uint16 = 1

	return *(*byte)(unsafe.Pointer(&a)) == 1
}

func htons(a uint16) uint16 {
	if isLittleEndian() {
		var arr [2]byte
		binary.LittleEndian.PutUint16(arr[:], a)
		return binary.BigEndian.Uint16(arr[:])
	}
	return a
}
