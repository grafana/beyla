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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/grafana/http-autoinstrument/pkg/goexec"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"
)

type EBPFTracer struct {
	Exec     string `yaml:"executable_name" env:"EXECUTABLE_NAME"`
	FuncName string `yaml:"func_name" env:"INSTRUMENT_FUNC_NAME"`

	Offsets *goexec.Offsets `yaml:"-"`
}

func EBPFTracerProvider(cfg EBPFTracer) node.StartFuncCtx[HTTPRequestTrace] {
	is, err := Instrument(cfg.Offsets)
	if err != nil {
		slog.Error("can't instantiate eBPF tracer", err)
		os.Exit(-1)
	}
	return is.Run
}

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 -type http_request_trace bpf ../../../bpf/go_nethttp.c -- -I../../../bpf/headers

// InstrumentedServe allows instrumenting each invocation to the Go standard net/http ServeHTTP
// method handler.
type InstrumentedServe struct {
	bpfObjects    bpfObjects
	uprobe        link.Link
	uprobeReturns []link.Link
	eventsReader  *ringbuf.Reader
}

// HTTPRequestTrace contains information from an HTTP request as directly received from the
// eBPF layer. This contains low-level C structures so for more comfortable handling from Go,
// HTTPRequestTrace instances are converted to spanner.HTTPRequestSpan instances in the
// spanner.ConvertToSpan function.
type HTTPRequestTrace bpfHttpRequestTrace

// Instrument the executable passed as path and insert probes in the provided offsets, so the
// returned InstrumentedServe instance will listen and forward traces for each HTTP invocation.
func Instrument(offsets *goexec.Offsets) (*InstrumentedServe, error) {
	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(offsets.FileInfo.ProExeLinkPath)
	if err != nil {
		return nil, fmt.Errorf("opening executable file %q: %w",
			offsets.FileInfo.ProExeLinkPath, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	if err := spec.RewriteConstants(offsets.Field); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}

	h := InstrumentedServe{}
	// Load BPF programs
	if err := spec.LoadAndAssign(&h.bpfObjects, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}
	// Attach BPF programs as start and return probes
	up, err := exe.Uprobe("", h.bpfObjects.UprobeServeHTTP, &link.UprobeOptions{
		Address: offsets.Func.Start,
	})
	if err != nil {
		return nil, fmt.Errorf("setting uprobe: %w", err)
	}
	h.uprobe = up

	// Go won't work with Uretprobes because the way it manages the stack. We need to set uprobes just before the return
	// values: https://github.com/iovisor/bcc/issues/1320
	for _, ret := range offsets.Func.Returns {
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

// TODO: make use of context to cancel process
func (h *InstrumentedServe) Run(_ context.Context, eventsChan chan<- HTTPRequestTrace) {
	logger := slog.With("name", "net/http-instrumentor")
	var event HTTPRequestTrace
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
