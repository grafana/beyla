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

package ebpf

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cilium/ebpf/rlimit"

	convenience "go.opentelemetry.io/obi/pkg/components/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/components/ebpf/tcmanager"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type flow_metrics_t -type flow_id_t  -type flow_record_t -target amd64,arm64 Net ../../../../bpf/netolly/flows.c -- -I../../../../bpf

const (
	// constants defined in flows.c as "volatile const"
	constSampling      = "sampling"
	aggregatedFlowsMap = "aggregated_flows"
	connInitiatorsMap  = "conn_initiators"
	flowDirectionsMap  = "flow_directions"
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
	cacheMaxSize  int
	enableIngress bool
	enableEgress  bool
}

func NewFlowFetcher(
	sampling, cacheMaxSize int,
	ingress, egress bool,
	ifaceManager *tcmanager.InterfaceManager,
	tcBackend tcmanager.TCBackend,
	rbSizeMB uint32,
	flushPeriod, flowDuration time.Duration,
	protocolWhitelist, protocolBlacklist []string,
) (*FlowFetcher, error) {
	protoWl, err := parseProtocolList(protocolWhitelist)
	if err != nil {
		return nil, fmt.Errorf("invalid protocol whitelist: %w", err)
	}

	protoBl, err := parseProtocolList(protocolBlacklist)
	if err != nil {
		return nil, fmt.Errorf("invalid protocol blacklist: %w", err)
	}

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

	ringBufferSize := effectiveRingBufferSize(rbSizeMB * 1024 * 1024)

	spec.Maps["direct_flows"].MaxEntries = ringBufferSize

	if err := spec.Variables["k_max_rb_size"].Set(ringBufferSize); err != nil {
		return nil, errors.New("failed to set ring buffer size")
	}

	if err := spec.Variables["k_rb_flush_period"].Set(uint64(flushPeriod)); err != nil {
		return nil, errors.New("failed to set ring buffer flush period")
	}

	if err := spec.Variables["k_max_flow_duration"].Set(uint64(flowDuration)); err != nil {
		return nil, errors.New("failed to set flow duration")
	}

	if err := spec.Variables["k_protocol_wl_empty"].Set(len(protocolWhitelist) == 0); err != nil {
		return nil, errors.New("failed to protocol white list empty")
	}

	if err := spec.Variables["k_protocol_bl_empty"].Set(len(protocolBlacklist) == 0); err != nil {
		return nil, errors.New("failed to set protocol black list empty")
	}

	// Resize aggregated flows and flow directions maps according to user-provided configuration
	spec.Maps[aggregatedFlowsMap].MaxEntries = uint32(cacheMaxSize)
	spec.Maps[flowDirectionsMap].MaxEntries = uint32(cacheMaxSize)
	spec.Maps[connInitiatorsMap].MaxEntries = uint32(cacheMaxSize)

	if err := convenience.RewriteConstants(spec, map[string]any{
		constSampling: uint32(sampling),
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	if err := assignProtocolList(objects.ProtocolWhitelist, protoWl); err != nil {
		return nil, err
	}

	if err := assignProtocolList(objects.ProtocolBlacklist, protoBl); err != nil {
		return nil, err
	}

	// read events from igress+egress ringbuffer
	flows, err := ringbuf.NewReader(objects.DirectFlows)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}

	tcManager := tcmanager.NewTCManager(tcBackend)
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
		cacheMaxSize:  cacheMaxSize,
		enableIngress: ingress,
		enableEgress:  egress,
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
		errs = append(errs, m.closeObjects()...)
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}

	if len(errs) > 0 {
		return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
	}

	return nil
}

func (m *FlowFetcher) closeObjects() []error {
	var errs []error
	if err := m.objects.ObiEgressFlowParse.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := m.objects.ObiIngressFlowParse.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := m.objects.AggregatedFlows.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := m.objects.DirectFlows.Close(); err != nil {
		errs = append(errs, err)
	}
	m.objects = nil
	return errs
}

func (m *FlowFetcher) ReadInto(r *ringbuf.Record) error {
	return m.ringbufReader.ReadInto(r)
}

func (m *FlowFetcher) logTCErrors(errors chan error) {
	for err := range errors {
		m.log.Warn("TCManager error", "error", err)
	}
}
