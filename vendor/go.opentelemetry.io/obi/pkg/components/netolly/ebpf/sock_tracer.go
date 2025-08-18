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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/containers/common/pkg/cgroupv2"

	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/components/netolly/flow/transport"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type flow_metrics_t -type flow_id_t  -type flow_record_t -target amd64,arm64 Net ../../../../bpf/netolly/flows_sock.c -- -I../../../../bpf

type SockFlowFetcher struct {
	log           *slog.Logger
	objects       *NetObjects
	ringbufReader *ringbuf.Reader
	links         []link.Link
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.FlowFetcher")
}

func getCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	enabled, err := cgroupv2.Enabled()
	if !enabled {
		if _, pathErr := os.Stat(filepath.Join(cgroupPath, "unified")); pathErr == nil {
			slog.Debug("discovered hybrid cgroup hierarchy, will attempt to attach sockops")
			return filepath.Join(cgroupPath, "unified"), nil
		}
		return "", errors.New("failed to find unified cgroup hierarchy: sockops cannot be used with cgroups v1")
	}
	return cgroupPath, err
}

func attachCgroup(program *ebpf.Program, attachType ebpf.AttachType, cgroupPath string) (link.Link, error) {
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  attachType,
		Program: program,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching cgroup program: %w", err)
	}

	return l, nil
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

func parseProtocolList(list []string) ([]transport.Protocol, error) {
	if len(list) == 0 {
		return []transport.Protocol{}, nil
	}

	ret := make([]transport.Protocol, 0, len(list))

	for _, s := range list {
		p, err := transport.ParseProtocol(s)
		if err != nil {
			return nil, err
		}

		ret = append(ret, p)
	}

	return ret, nil
}

func assignProtocolList(m *ebpf.Map, list []transport.Protocol) error {
	for _, proto := range list {
		if err := m.Put(uint32(proto), uint8(1)); err != nil {
			return fmt.Errorf("error writing map: %w", err)
		}
	}

	return nil
}

func NewSockFlowFetcher(rbSizeMB uint32, flushPeriod, flowDuration time.Duration,
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
		return nil, errors.New("failed to set flow duration")
	}

	if err := spec.Variables["k_protocol_bl_empty"].Set(len(protocolBlacklist) == 0); err != nil {
		return nil, errors.New("failed to set flow duration")
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

	cgroupPath, err := getCgroupPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get cgroup path: %w", err)
	}

	links := []link.Link{}

	for prog, attachType := range map[*ebpf.Program]ebpf.AttachType{
		objects.ObiSockEgress:  ebpf.AttachCGroupInetEgress,
		objects.ObiSockIngress: ebpf.AttachCGroupInetIngress,
		objects.ObiSockRelease: ebpf.AttachCgroupInetSockRelease,
		objects.ObiSockOps:     ebpf.AttachCGroupSockOps,
	} {
		lnk, err := attachCgroup(prog, attachType, cgroupPath)
		if err != nil {
			return nil, fmt.Errorf("error attaching cgroup program: %w", err)
		}

		links = append(links, lnk)
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
		links:         links,
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

	for _, l := range m.links {
		l.Close()
	}

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
		if err := m.objects.DirectFlows.Close(); err != nil {
			errs = append(errs, err)
		}
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

func (m *SockFlowFetcher) ReadInto(rec *ringbuf.Record) error {
	return m.ringbufReader.ReadInto(rec)
}
