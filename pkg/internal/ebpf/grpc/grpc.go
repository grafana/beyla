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

package grpc

import (
	"context"
	"io"
	"log/slog"
	"unsafe"

	"github.com/cilium/ebpf"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/go_grpc.c -- -I../../../../bpf/headers -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/go_grpc.c -- -I../../../../bpf/headers -DBPF_DEBUG -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp ../../../../bpf/go_grpc.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_debug ../../../../bpf/go_grpc.c -- -I../../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	log        *slog.Logger
	pidsFilter *ebpfcommon.PIDsFilter
	cfg        *ebpfcommon.TracerConfig
	metrics    imetrics.Reporter

	bpfObjects bpfObjects
	closers    []io.Closer
}

func New(cfg *ebpfcommon.TracerConfig, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "grpc.Tracer")
	return &Tracer{
		log:        log,
		cfg:        cfg,
		metrics:    metrics,
		pidsFilter: ebpfcommon.NewPIDsFilter(log),
	}
}

func (p *Tracer) AllowPID(pid uint32, _ svc.ID) {
	p.pidsFilter.AllowPID(pid)
}

func (p *Tracer) BlockPID(pid uint32) {
	p.pidsFilter.BlockPID(pid)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.BpfDebug {
		loader = loadBpf_debug
	}

	if ebpfcommon.SupportsContextPropagation(p.log) {
		loader = loadBpf_tp
		if p.cfg.BpfDebug {
			loader = loadBpf_tp_debug
		}
	} else {
		p.log.Info("Kernel in lockdown mode, trace info propagation in gRPC headers is disabled.")
	}
	return loader()
}

func (p *Tracer) Constants(_ *exec.FileInfo, offsets *goexec.Offsets) map[string]any {
	// Set the field offsets and the logLevel for grpc BPF program,
	// as well as some other configuration constants
	constants := map[string]any{
		"wakeup_data_bytes": uint32(p.cfg.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{})),
	}
	for _, s := range []string{
		"grpc_stream_st_ptr_pos",
		"grpc_stream_method_ptr_pos",
		"grpc_status_s_pos",
		"grpc_status_code_ptr_pos",
		"grpc_st_remoteaddr_ptr_pos",
		"grpc_st_localaddr_ptr_pos",
		"tcp_addr_port_ptr_pos",
		"tcp_addr_ip_ptr_pos",
		"grpc_client_target_ptr_pos",
		"grpc_stream_ctx_ptr_pos",
		"value_context_val_ptr_pos",
		"http2_client_next_id_pos",
		"hpack_encoder_w_pos",
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
	m := map[string]ebpfcommon.FunctionPrograms{
		"google.golang.org/grpc.(*Server).handleStream": {
			Required: true,
			Start:    p.bpfObjects.UprobeServerHandleStream,
			End:      p.bpfObjects.UprobeServerHandleStreamReturn,
		},
		"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus": {
			Required: true,
			Start:    p.bpfObjects.UprobeTransportWriteStatus,
		},
		"google.golang.org/grpc.(*ClientConn).Invoke": {
			Required: true,
			Start:    p.bpfObjects.UprobeClientConnInvoke,
			End:      p.bpfObjects.UprobeClientConnInvokeReturn,
		},
		"google.golang.org/grpc.(*ClientConn).NewStream": {
			Required: true,
			Start:    p.bpfObjects.UprobeClientConnNewStream,
		},
	}

	if ebpfcommon.SupportsContextPropagation(p.log) {
		m["golang.org/x/net/http2/hpack.(*Encoder).WriteField"] = ebpfcommon.FunctionPrograms{
			Required: true,
			Start:    p.bpfObjects.UprobeHpackEncoderWriteField,
		}
		m["google.golang.org/grpc/internal/transport.(*http2Client).NewStream"] = ebpfcommon.FunctionPrograms{
			Required: true,
			Start:    p.bpfObjects.UprobeTransportHttp2ClientNewStream,
		}
		m["google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader"] = ebpfcommon.FunctionPrograms{
			Required: true,
			Start:    p.bpfObjects.UprobeTransportLoopyWriterWriteHeader,
			End:      p.bpfObjects.UprobeTransportLoopyWriterWriteHeaderReturn,
		}
	}

	return m
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

func (p *Tracer) RecordInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span, service svc.ID) {
	ebpfcommon.ForwardRingbuf[ebpfcommon.HTTPRequestTrace](
		service,
		p.cfg, p.log, p.bpfObjects.Events,
		ebpfcommon.ReadHTTPRequestTraceAsSpan,
		p.pidsFilter.Filter,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}
