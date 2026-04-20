// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Copyright Red Hat / IBM
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

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gavv/monotime"

	"go.opentelemetry.io/obi/pkg/config"
	convenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type flow_metrics_t -type flow_id_t -type flow_record_t -type packet_count_t -target amd64,arm64 Net ../../../../bpf/netolly/flows.c -- -I../../../../bpf

const (
	// constants defined in flows.c as "volatile const"
	constSampling      = "sampling"
	constTraceMessages = "trace_messages"
	constPortGuessing  = "port_guessing"
	aggregatedFlowsMap = "aggregated_flows"
	connInitiatorsMap  = "conn_initiators"
	flowDirectionsMap  = "flow_directions"

	// const defined in bpf/common/globals.h as "volatile const"
	gBpfDebug = "g_bpf_debug"
)

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.FlowFetcher")
}

// FlowFetcher reads and forwards the Flows from the Traffic Control hooks in the eBPF kernel space.
// It provides access both to flows that are aggregated in the kernel space (via PerfCPU hashmap)
// and to flows that are forwarded by the kernel via ringbuffer because could not be aggregated
// in the map
type FlowFetcher struct {
	log           *slog.Logger
	objects       *NetObjects
	ringbufReader *ringbuf.Reader
	tcManager     tcmanager.TCManager
	enableIngress bool
	enableEgress  bool
	flowMapReader flowMapReader
}

func NewFlowFetcher(
	sampling, cacheMaxSize int,
	ingress, egress bool,
	ifaceManager *tcmanager.InterfaceManager,
	portGuessPolicy flowdef.PortGuessPolicy,
	cfg *config.EBPFTracer,
) (*FlowFetcher, error) {
	startTime := uint64(monotime.Now())
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := NetObjects{}
	spec, err := LoadNet()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// Resize aggregated flows and flow directions maps according to user-provided configuration
	spec.Maps[aggregatedFlowsMap].MaxEntries = uint32(cacheMaxSize)
	spec.Maps[flowDirectionsMap].MaxEntries = uint32(cacheMaxSize)
	spec.Maps[connInitiatorsMap].MaxEntries = uint32(cacheMaxSize)

	// Apply global map scaling factor
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
		return nil, fmt.Errorf("loading netolly eBPF spec: %w", err)
	}

	// read events from igress+egress ringbuffer
	flows, err := ringbuf.NewReader(objects.DirectFlows)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}

	tcManager := tcmanager.NewTCManager(cfg.TCBackend)
	tcManager.SetInterfaceManager(ifaceManager)

	if egress {
		tcManager.AddProgram("tc/egress_flow_parse", objects.ObiEgressFlowParse, tcmanager.AttachmentEgress)
	}

	if ingress {
		tcManager.AddProgram("tc/ingress_flow_parse", objects.ObiIngressFlowParse, tcmanager.AttachmentIngress)
	}

	fetcher := &FlowFetcher{
		log:           tlog,
		objects:       &objects,
		ringbufReader: flows,
		tcManager:     tcManager,
		enableIngress: ingress,
		enableEgress:  egress,
		flowMapReader: chooseMapReader(cfg.ForceBPFMapReader, objects.AggregatedFlows, cacheMaxSize, startTime),
	}

	// errors are not critical for this tracer
	go fetcher.logTCErrors(tcManager.Errors())

	return fetcher, nil
}

// Close the eBPF fetcher from the system.
// We don't need an "Close(iface)" method because the filters and qdiscs
// are automatically removed when the interface is down
func (m *FlowFetcher) Close() error {
	log := tlog()
	log.Debug("unregistering eBPF objects")

	m.tcManager.Shutdown()

	var errs []error
	// m.ringbufReader.Read is a blocking operation, so we need to close the ring buffer
	// from another goroutine to avoid the system not being able to exit if there
	// isn't traffic in a given interface
	if m.ringbufReader != nil {
		if err := m.ringbufReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if m.objects != nil {
		if err := m.objects.Close(); err != nil {
			errs = append(errs, err)
		}
		m.objects = nil
	}
	return errors.Join(errs...)
}

func (m *FlowFetcher) FlowPacketStatsMap() *ebpf.Map {
	return m.objects.FlowPacketStats
}

func (m *FlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}

func (m *FlowFetcher) LookupAndDeleteMap() map[NetFlowId]*NetFlowMetrics {
	flows, err := m.flowMapReader.lookupAndDeleteMap()
	if err != nil {
		m.log.Error("failed to read flows from eBPF map", "error", err)
	}
	return flows
}

func (m *FlowFetcher) logTCErrors(errors chan error) {
	for err := range errors {
		m.log.Warn("TCManager error", "error", err)
	}
}
