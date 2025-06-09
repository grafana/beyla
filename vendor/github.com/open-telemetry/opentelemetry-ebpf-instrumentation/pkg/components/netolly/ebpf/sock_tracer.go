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

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	convenience "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/convenience"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type flow_metrics_t -type flow_id_t  -type flow_record_t -target amd64,arm64 NetSk ../../../../bpf/netolly/flows_sock.c -- -I../../../../bpf

// SockFlowFetcher reads and forwards the Flows from the eBPF kernel space with a socket filter implementation.
// It provides access both to flows that are aggregated in the kernel space (via PerfCPU hashmap)
// and to flows that are forwarded by the kernel via ringbuffer because could not be aggregated
// in the map
type SockFlowFetcher struct {
	log           *slog.Logger
	objects       *NetSkObjects
	ringbufReader *ringbuf.Reader
	cacheMaxSize  int
}

func NewSockFlowFetcher(
	sampling, cacheMaxSize int,
) (*SockFlowFetcher, error) {
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

	traceMsgs := 0
	if tlog.Enabled(context.TODO(), slog.LevelDebug) {
		traceMsgs = 1
	}
	if err := convenience.RewriteConstants(spec, map[string]any{
		constSampling:      uint32(sampling),
		constTraceMessages: uint8(traceMsgs),
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}
	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 640 * 1024},
	}); err != nil {
		printVerifierErrorInfo(err)
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err == nil {
		ssoErr := syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, objects.BeylaSocketHttpFilter.FD())
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
		cacheMaxSize:  cacheMaxSize,
	}, nil
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
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
	if m.objects != nil {
		errs = append(errs, m.closeObjects()...)
	}
	if len(errs) == 0 {
		return nil
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

func (m *SockFlowFetcher) closeObjects() []error {
	var errs []error
	if err := m.objects.BeylaSocketHttpFilter.Close(); err != nil {
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

func (m *SockFlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}

// LookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// It returns a map where the key
// For synchronization purposes, we get/delete a whole snapshot of the flows map.
// This way we avoid missing packets that could be updated on the
// ebpf side while we process/aggregate them here
// Changing this method invocation by BatchLookupAndDelete could improve performance
// TODO: detect whether BatchLookupAndDelete is supported (Kernel>=5.6) and use it selectively
// Supported Lookup/Delete operations by kernel: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
// Race conditions here causes that some flows are lost in high-load scenarios
func (m *SockFlowFetcher) LookupAndDeleteMap() map[NetFlowId][]NetFlowMetrics {
	flowMap := m.objects.AggregatedFlows

	iterator := flowMap.Iterate()
	flows := make(map[NetFlowId][]NetFlowMetrics, m.cacheMaxSize)

	id := NetFlowId{}
	var metrics []NetFlowMetrics
	// Changing Iterate+Delete by LookupAndDelete would prevent some possible race conditions
	// TODO: detect whether LookupAndDelete is supported (Kernel>=4.20) and use it selectively
	for iterator.Next(&id, &metrics) {
		if err := flowMap.Delete(id); err != nil {
			m.log.Debug("couldn't delete flow entry", "flowId", id, "error", err)
		}
		// We observed that eBFP PerCPU map might insert multiple times the same key in the map
		// (probably due to race conditions) so we need to re-join metrics again at userspace
		// TODO: instrument how many times the keys are is repeated in the same eviction
		flows[id] = append(flows[id], metrics...)
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
