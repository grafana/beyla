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
	"os"

	"github.com/open-telemetry/opentelemetry-go-instrumentation/pkg/instrumentors/bpffs"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/open-telemetry/opentelemetry-go-instrumentation/pkg/inject"
	"github.com/open-telemetry/opentelemetry-go-instrumentation/pkg/instrumentors/context"
	"golang.org/x/exp/slog"
)

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_request_trace bpf ../../../bpf/go_nethttp.c -- -I../../../bpf/headers

type httpServerInstrumentor struct {
	bpfObjects   *bpfObjects
	uprobe       link.Link
	returnProbs  []link.Link
	eventsReader *perf.Reader
}

type HttpRequestTrace bpfHttpRequestTrace

func New() *httpServerInstrumentor {
	return &httpServerInstrumentor{}
}

func (h *httpServerInstrumentor) LibraryName() string {
	return "net/http"
}

func (h *httpServerInstrumentor) FuncNames() []string {
	return []string{"net/http.(*ServeMux).ServeHTTP"}
}

func (h *httpServerInstrumentor) Load(ctx *context.InstrumentorContext) error {
	spec, err := ctx.Injector.Inject(loadBpf, "go", ctx.TargetDetails.GoVersion.Original(), []*inject.InjectStructField{
		{
			VarName:    "method_ptr_pos",
			StructName: "net/http.Request",
			Field:      "Method",
		},
		{
			VarName:    "url_ptr_pos",
			StructName: "net/http.Request",
			Field:      "URL",
		},
		{
			VarName:    "ctx_ptr_pos",
			StructName: "net/http.Request",
			Field:      "ctx",
		},
		{
			VarName:    "path_ptr_pos",
			StructName: "net/url.URL",
			Field:      "Path",
		},
	}, false)

	if err != nil {
		return err
	}

	h.bpfObjects = &bpfObjects{}
	err = spec.LoadAndAssign(h.bpfObjects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpffs.BpfFsPath,
		},
	})
	if err != nil {
		return err
	}

	offset, err := ctx.TargetDetails.GetFunctionOffset(h.FuncNames()[0])
	if err != nil {
		return err
	}

	up, err := ctx.Executable.Uprobe("", h.bpfObjects.UprobeServerMuxServeHTTP, &link.UprobeOptions{
		Offset: offset,
	})
	if err != nil {
		return err
	}

	h.uprobe = up
	retOffsets, err := ctx.TargetDetails.GetFunctionReturns(h.FuncNames()[0])
	if err != nil {
		return err
	}

	for _, ret := range retOffsets {
		retProbe, err := ctx.Executable.Uprobe("", h.bpfObjects.UprobeServerMuxServeHTTP_Returns, &link.UprobeOptions{
			Offset: ret,
		})
		if err != nil {
			return err
		}
		h.returnProbs = append(h.returnProbs, retProbe)
	}

	rd, err := perf.NewReader(h.bpfObjects.Events, os.Getpagesize())
	if err != nil {
		return err
	}
	h.eventsReader = rd

	return nil
}

func (h *httpServerInstrumentor) Run(eventsChan chan<- HttpRequestTrace) {
	logger := slog.With("name", "net/http-instrumentor")
	var event HttpRequestTrace
	for {
		record, err := h.eventsReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			logger.Error("error reading from perf reader", err)
			continue
		}

		if record.LostSamples != 0 {
			logger.Info("perf event ring buffer full", "dropped", record.LostSamples)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Error("error parsing perf event", err)
			continue
		}

		eventsChan <- event
	}
}

/*
func (h *httpServerInstrumentor) convertEvent(e *HttpEvent) *events.Event {
	method := unix.ByteSliceToString(e.Method[:])
	path := unix.ByteSliceToString(e.Path[:])

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    e.SpanContext.TraceID,
		SpanID:     e.SpanContext.SpanID,
		TraceFlags: trace.FlagsSampled,
	})

	return &events.Event{
		Library:     h.LibraryName(),
		Name:        path,
		Kind:        trace.SpanKindServer,
		StartTime:   int64(e.StartTime),
		EndTime:     int64(e.EndTime),
		SpanContext: &sc,
		Attributes: []attribute.KeyValue{
			semconv.HTTPMethodKey.String(method),
			semconv.HTTPTargetKey.String(path),
		},
	}
}
*/

func (h *httpServerInstrumentor) Close() {
	slog.With("name", "net/http-instrumentor").Info("closing net/http instrumentor")
	if h.eventsReader != nil {
		h.eventsReader.Close()
	}

	if h.uprobe != nil {
		h.uprobe.Close()
	}

	for _, r := range h.returnProbs {
		r.Close()
	}

	if h.bpfObjects != nil {
		h.bpfObjects.Close()
	}
}
