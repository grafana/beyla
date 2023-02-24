// Copyright The OpenTelemetry Authors
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

package nethttp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/grafana/http-autoinstrument/pkg/exec"
	"golang.org/x/exp/slog"
)

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_request_trace bpf ../../../bpf/go_nethttp.c -- -I../../../bpf/headers

// InstrumentedServe allows instrumenting each invocation to the Go standard net/http ServeHTTP
// method handler.
type InstrumentedServe struct {
	bpfObjects    bpfObjects
	uprobe        link.Link
	uprobeReturns []link.Link
	eventsReader  *ringbuf.Reader
}

// HttpRequestTrace contains information from an HTTP request as directly received from the
// eBPF layer. This contains low-level C structures so for more comfortable handling from Go,
// HttpRequestTrace instances are converted to spanner.HttpRequestSpan instances in the
// spanner.ConvertToSpan function.
type HttpRequestTrace bpfHttpRequestTrace

// Instrument the executable passed as path and insert probes in the provided offsets, so the
// returned InstrumentedServe instance will listen and forward traces for each HTTP invocation.
func Instrument(processPath string, offsets exec.FuncOffsets) (*InstrumentedServe, error) {
	exe, err := link.OpenExecutable(processPath)
	if err != nil {
		return nil, fmt.Errorf("opening executable file %q: %w", processPath, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// TODO: fill this information from DWARF info
	if err := spec.RewriteConstants(map[string]interface{}{
		"url_ptr_pos":    uint64(16),
		"path_ptr_pos":   uint64(56),
		"method_ptr_pos": uint64(0),
		"status_ptr_pos": uint64(120),
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}

	h := InstrumentedServe{}
	// Load BPF programs
	if err := spec.LoadAndAssign(&h.bpfObjects, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}
	// Attach BPF programs as start and return probes
	up, err := exe.Uprobe("", h.bpfObjects.UprobeServeHTTP, &link.UprobeOptions{
		Address: offsets.Start,
	})
	if err != nil {
		return nil, fmt.Errorf("setting uprobe: %w", err)
	}
	h.uprobe = up

	// Go won't work with Uretprobes because the way it manages the stack. We need to set uprobes just before the return
	// values: https://github.com/iovisor/bcc/issues/1320
	for _, ret := range offsets.Returns {
		urp, err := exe.Uprobe("", h.bpfObjects.UprobeServeHttpReturn, &link.UprobeOptions{
			Address: ret,
		})
		if err != nil {
			return nil, fmt.Errorf("setting uretpobe: %w", err)
		}
		h.uprobeReturns = append(h.uprobeReturns, urp)
	}

	// BPF will send each measured trace via Ring Buffer, so we listen for them from the
	// user space.
	rd, err := ringbuf.NewReader(h.bpfObjects.Events)
	if err != nil {
		return nil, fmt.Errorf("creating perf reader: %w", err)
	}
	h.eventsReader = rd

	return &h, nil
}

func (h *InstrumentedServe) Run(eventsChan chan<- HttpRequestTrace) {
	logger := slog.With("name", "net/http-instrumentor")
	var event HttpRequestTrace
	for {
		logger.Debug("starting to read perf buffer")
		record, err := h.eventsReader.Read()
		logger.Debug("received event")
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Error("error reading from perf reader", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Error("error parsing perf event", err)
			continue
		}

		eventsChan <- event
	}
}

func (h *InstrumentedServe) Close() {
	slog.With("name", "net/http-instrumentor").Info("closing net/http instrumentor")
	if h.eventsReader != nil {
		h.eventsReader.Close()
	}

	if h.uprobe != nil {
		h.uprobe.Close()
	}
	for _, urp := range h.uprobeReturns {
		urp.Close()
	}

	h.bpfObjects.Close()
}
