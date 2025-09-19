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

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	convenience "go.opentelemetry.io/obi/pkg/components/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
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

func effectiveRingBufferSize(size uint32) uint32 {
	page := uint32(os.Getpagesize())

	// ensure size is at least the system page size.
	if size < page {
		size = page
	}

	// if size is already a power of two, this trick will leave it unchanged.
	// decrement size so powers of two won't get rounded up.
	size--

	// fill all bits to the right with 1s
	// this propagates the highest set bit to all lower bits.
	size |= size >> 1
	size |= size >> 2
	size |= size >> 4
	size |= size >> 8
	size |= size >> 16

	// increment to get the next power of two.
	size++

	return size
}

func NewSockFlowFetcher(
	sampling, cacheMaxSize int,
	rbSizeMB uint32,
	flushPeriod, flowDuration time.Duration,
	protocolWhitelist, protocolBlacklist []string,
) (*SockFlowFetcher, error) {
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

	objects := NetSkObjects{}
	spec, err := LoadNetSk()
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
	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 640 * 1024},
	}); err != nil {
		printVerifierErrorInfo(err)
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	if err := assignProtocolList(objects.ProtocolWhitelist, protoWl); err != nil {
		return nil, err
	}

	if err := assignProtocolList(objects.ProtocolBlacklist, protoBl); err != nil {
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
	if err := m.objects.ObiSocketFilter.Close(); err != nil {
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

func (m *SockFlowFetcher) ReadInto(r *ringbuf.Record) error {
	return m.ringbufReader.ReadInto(r)
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
