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
	"log/slog"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/grafana/beyla/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/go_nethttp.c -- -I../../../../bpf/headers -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/go_nethttp.c -- -I../../../../bpf/headers -DBPF_DEBUG -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp ../../../../bpf/go_nethttp.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_debug ../../../../bpf/go_nethttp.c -- -I../../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	log        *slog.Logger
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *ebpfcommon.TracerConfig
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
}

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "nethttp.Tracer")
	return &Tracer{
		log:        log,
		pidsFilter: ebpfcommon.CommonPIDsFilter(cfg.Discovery.SystemWide),
		cfg:        &cfg.EBPF,
		metrics:    metrics,
	}
}

func (p *Tracer) AllowPID(pid, ns uint32, svc svc.ID) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeGo)
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
}

func (p *Tracer) supportsContextPropagation() bool {
	return !ebpfcommon.IntegrityModeOverride && ebpfcommon.SupportsContextPropagation(p.log)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.BpfDebug {
		loader = loadBpf_debug
	}

	if p.supportsContextPropagation() {
		loader = loadBpf_tp
		if p.cfg.BpfDebug {
			loader = loadBpf_tp_debug
		}
	} else {
		p.log.Info("Kernel in lockdown mode, trace info propagation in HTTP headers is disabled.")
	}
	return loader()
}

func (p *Tracer) Constants(_ *exec.FileInfo, offsets *goexec.Offsets) map[string]any {
	// Set the field offsets and the logLevel for nethttp BPF program,
	// as well as some other configuration constants
	constants := map[string]any{
		"wakeup_data_bytes": uint32(p.cfg.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{})),
	}
	for _, s := range []string{
		"url_ptr_pos",
		"path_ptr_pos",
		"method_ptr_pos",
		"status_ptr_pos",
		"status_code_ptr_pos",
		"content_length_ptr_pos",
		"req_header_ptr_pos",
		"io_writer_buf_ptr_pos",
		"io_writer_n_pos",
		"tcp_addr_port_ptr_pos",
		"tcp_addr_ip_ptr_pos",
		"c_rwc_pos",
		"pc_conn_pos",
		"rwc_conn_pos",
		"conn_fd_pos",
		"fd_laddr_pos",
		"fd_raddr_pos",
	} {
		constants[s] = offsets.Field[s]
	}

	// Optional list
	for _, s := range []string{
		"rws_status_pos",
		"cc_next_stream_id_pos",
		"framer_w_pos",
		"rws_conn_pos",
		"http2_server_conn_pos",
		"cc_tconn_pos",
	} {
		constants[s] = offsets.Field[s]
		if constants[s] == nil {
			constants[s] = uint64(0xffffffffffffffff)
		}
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
		"net/http.serverHandler.ServeHTTP": {
			Start: p.bpfObjects.UprobeServeHTTP,
			End:   p.bpfObjects.UprobeServeHTTPReturns,
		},
		"net/http.(*conn).readRequest": {
			End: p.bpfObjects.UprobeReadRequestReturns,
		},
		"net/http.(*Transport).roundTrip": { // HTTP client, works with Client.Do as well as using the RoundTripper directly
			Start: p.bpfObjects.UprobeRoundTrip,
			End:   p.bpfObjects.UprobeRoundTripReturn,
		},
		"golang.org/x/net/http2.(*ClientConn).roundTrip": { // http2 client after 0.22
			Start: p.bpfObjects.UprobeHttp2RoundTrip,
			End:   p.bpfObjects.UprobeRoundTripReturn, // return is the same as for http 1.1
		},
		"golang.org/x/net/http2.(*ClientConn).RoundTrip": { // http2 client
			Start: p.bpfObjects.UprobeHttp2RoundTrip,
			End:   p.bpfObjects.UprobeRoundTripReturn, // return is the same as for http 1.1
		},
		"golang.org/x/net/http2.(*responseWriterState).writeHeader": { // http2 server request done, capture the response code
			Start: p.bpfObjects.UprobeHttp2ResponseWriterStateWriteHeader,
		},
		// tracking of tcp connections for black-box propagation
		"net/http.(*conn).serve": { // http server
			Start: p.bpfObjects.UprobeConnServe,
			End:   p.bpfObjects.UprobeConnServeRet,
		},
		"net.(*netFD).Read": {
			Start: p.bpfObjects.UprobeNetFdRead,
		},
		"net/http.(*persistConn).roundTrip": { // http client
			Start: p.bpfObjects.UprobePersistConnRoundTrip,
		},
		// sql
		"database/sql.(*DB).queryDC": {
			Start: p.bpfObjects.UprobeQueryDC,
			End:   p.bpfObjects.UprobeQueryReturn,
		},
		"database/sql.(*DB).execDC": {
			Start: p.bpfObjects.UprobeExecDC,
			End:   p.bpfObjects.UprobeQueryReturn,
		},
	}

	if p.supportsContextPropagation() {
		m["net/http.Header.writeSubset"] = ebpfcommon.FunctionPrograms{
			Start: p.bpfObjects.UprobeWriteSubset, // http 1.x context propagation
		}
		m["golang.org/x/net/http2.(*Framer).WriteHeaders"] = ebpfcommon.FunctionPrograms{ // http2 context propagation
			Start: p.bpfObjects.UprobeHttp2FramerWriteHeaders,
			End:   p.bpfObjects.UprobeHttp2FramerWriteHeadersReturns,
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

func (p *Tracer) Tracepoints() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span) {
	ebpfcommon.SharedRingbuf(
		p.cfg,
		p.pidsFilter,
		p.bpfObjects.Events,
		p.metrics,
	)(ctx, append(p.closers, &p.bpfObjects), eventsChan)
}
