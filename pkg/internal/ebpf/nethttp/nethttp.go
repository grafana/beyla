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
	"context"
	"io"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/exp/slog"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf/common"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/exec"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/goexec"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/imetrics"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/go_nethttp.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/go_nethttp.c -- -I../../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	Cfg        *ebpfcommon.TracerConfig
	Metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.Cfg.BpfDebug {
		loader = loadBpf_debug
	}
	return loader()
}

func (p *Tracer) Constants(_ *exec.FileInfo, offsets *goexec.Offsets) map[string]any {
	// Set the field offsets and the logLevel for nethttp BPF program,
	// as well as some other configuration constants
	constants := map[string]any{
		"wakeup_data_bytes": uint32(p.Cfg.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{})),
	}
	for _, s := range []string{
		"url_ptr_pos",
		"path_ptr_pos",
		"method_ptr_pos",
		"status_ptr_pos",
		"status_code_ptr_pos",
		"remoteaddr_ptr_pos",
		"host_ptr_pos",
		"content_length_ptr_pos",
		"resp_req_pos",
	} {
		constants[s] = offsets.Field[s]
	}
	return constants
}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string]ebpfcommon.FunctionPrograms {
	return map[string]ebpfcommon.FunctionPrograms{
		"net/http.HandlerFunc.ServeHTTP": {
			Required: true,
			Start:    p.bpfObjects.UprobeServeHTTP,
		},
		"net/http.(*connReader).startBackgroundRead": {
			Start: p.bpfObjects.UprobeStartBackgroundRead,
		},
		"net/http.(*response).WriteHeader": {
			Start: p.bpfObjects.UprobeWriteHeader,
		},
		"net/http.(*Client).send": {
			Start: p.bpfObjects.UprobeClientSend,
			End:   p.bpfObjects.UprobeClientSendReturn,
		},
	}
}

func (p *Tracer) KProbes() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []any) {
	logger := slog.With("component", "nethttp.Tracer")
	ebpfcommon.ForwardRingbuf(
		p.Cfg, logger, p.bpfObjects.Events, ebpfcommon.Read[ebpfcommon.HTTPRequestTrace],
		p.Metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

// GinTracer overrides Tracer to inspect the Gin ServeHTTP endpoint
type GinTracer struct {
	Tracer
}

func (p *GinTracer) GoProbes() map[string]ebpfcommon.FunctionPrograms {
	return map[string]ebpfcommon.FunctionPrograms{
		"github.com/gin-gonic/gin.(*Engine).ServeHTTP": {
			Required: true,
			Start:    p.bpfObjects.UprobeServeHTTP,
		},
		"net/http.(*response).WriteHeader": {
			Start: p.bpfObjects.UprobeWriteHeader,
		},
	}
}

func (p *GinTracer) Run(ctx context.Context, eventsChan chan<- []any) {
	logger := slog.With("component", "nethttp.GinTracer")
	ebpfcommon.ForwardRingbuf(
		p.Cfg, logger, p.bpfObjects.Events, ebpfcommon.Read[ebpfcommon.HTTPRequestTrace],
		p.Metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}
