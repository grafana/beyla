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
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/context"
	"golang.org/x/exp/slog"
)

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 -type http_request_trace bpf ../../../bpf/go_nethttp.c -- -I../../../bpf/headers

type httpServerInstrumentor struct {
	bpfObjects   *bpfObjects
	uprobe       link.Link
	uretProbe    link.Link
	eventsReader *perf.Reader
}

type HttpRequestTrace bpfHttpRequestTrace

func New() *httpServerInstrumentor {
	return &httpServerInstrumentor{}
}

func (h *httpServerInstrumentor) LibraryName() string {
	return "net/http"
}

/*
&dwarf.Entry{Offset:0x25a449,

Tag:dwarf.TagSubprogram,
Children:true,

	Field:[]dwarf.Field{
		dwarf.Field{
			Attr:dwarf.AttrName, Val:"net/http.(*ServeMux).ServeHTTP", Class:dwarf.ClassString
		},
		dwarf.Field{Attr:dwarf.AttrLowpc,  ## ESTE ES
			Val:0x6973e0, Class:dwarf.ClassAddress
		},

dwarf.Field{Attr:dwarf.AttrHighpc, Val:0x697565, Class:dwarf.ClassAddress}, dwarf.Field{Attr:dwarf.AttrFrameBase, Val:[]uint8{0x9c}, Class:dwarf.ClassExprLoc}, dwarf.Field{Attr:dwarf.AttrDeclFile, Val:19, Class:dwarf.ClassConstant}, dwarf.Field{Attr:dwarf.AttrExternal, Val:true, Class:dwarf.ClassFlag}}}
*/
func (h *httpServerInstrumentor) FuncNames() []string {
	return []string{"net/http.HandlerFunc.ServeHTTP"}
}

func (h *httpServerInstrumentor) Load(ctx *context.InstrumentorContext) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}
	objects := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading BPF data: %w", err)
	}
	// TODO: adapt ctx.Injector.Inject and later dwarf info
	if err := spec.RewriteConstants(map[string]interface{}{
		"url_ptr_pos":    uint64(16),
		"path_ptr_pos":   uint64(56),
		"ctx_ptr_pos":    uint64(232),
		"method_ptr_pos": uint64(0),
	}); err != nil {
		return fmt.Errorf("rewriting BPF constants definition: %w", err)
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	h.bpfObjects = &objects

	serveFunc, ok := ctx.TargetDetails.Functions[h.FuncNames()[0]]
	if !ok {
		return fmt.Errorf("can't find function: %v", h.FuncNames()[0])
	}
	_ = serveFunc

	// this is starting to work despite serveFunc.Offset is 0 for this actual function
	up, err := ctx.Executable.Uprobe("net/http.HandlerFunc.ServeHTTP", h.bpfObjects.UprobeServerMuxServeHTTP, &link.UprobeOptions{
		Address: serveFunc.Offset,
	})
	if err != nil {
		return fmt.Errorf("setting uprobe: %w", err)
	}

	h.uprobe = up

	urp, err := ctx.Executable.Uretprobe("net/http.HandlerFunc.ServeHTTP", h.bpfObjects.UprobeServerMuxServeHTTP_Returns, &link.UprobeOptions{
		Address: serveFunc.Offset,
	})
	if err != nil {
		return fmt.Errorf("setting uretpobe: %w", err)
	}
	h.uretProbe = urp

	rd, err := perf.NewReader(h.bpfObjects.Events, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf reader: %w", err)
	}
	h.eventsReader = rd

	return nil
}

func (h *httpServerInstrumentor) Run(eventsChan chan<- HttpRequestTrace) {
	logger := slog.With("name", "net/http-instrumentor")
	var event HttpRequestTrace
	for {
		logger.Info("starting to read event")
		record, err := h.eventsReader.Read()
		logger.Info("received event")
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
	if h.uretProbe != nil {
		h.uretProbe.Close()
	}

	if h.bpfObjects != nil {
		h.bpfObjects.Close()
	}
}
