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

package kafkago

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

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/go_kafka_seg.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/go_kafka_seg.c -- -I../../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	log        *slog.Logger
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *ebpfcommon.TracerConfig
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
}

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "kafkago.Tracer")
	return &Tracer{
		log:        log,
		cfg:        &cfg.EBPF,
		metrics:    metrics,
		pidsFilter: ebpfcommon.CommonPIDsFilter(cfg.Discovery.SystemWide),
	}
}

func (p *Tracer) AllowPID(pid, ns uint32, svc svc.ID) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeGo)
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.BpfDebug {
		loader = loadBpf_debug
	}
	return loader()
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) Constants(_ *exec.FileInfo, offsets *goexec.Offsets) map[string]any {
	// Set the field offsets and the logLevel for grpc BPF program,
	// as well as some other configuration constants
	constants := map[string]any{
		"wakeup_data_bytes": uint32(p.cfg.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{})),
	}

	for _, s := range []string{
		"conn_fd_pos",
		"fd_laddr_pos",
		"fd_raddr_pos",
		"tcp_addr_port_ptr_pos",
		"tcp_addr_ip_ptr_pos",
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
		"github.com/segmentio/kafka-go.(*Writer).produce": { // stores the current topic
			Start:    p.bpfObjects.UprobeWriterProduce,
			Required: true,
		},
		"github.com/segmentio/kafka-go.(*Client).roundTrip": { // has the goroutine connection with (*Writer).produce and msg* connection with protocol.RoundTrip
			Start:    p.bpfObjects.UprobeClientRoundTrip,
			Required: true,
		},
		"github.com/segmentio/kafka-go/protocol.RoundTrip": { // used for collecting the connection information
			Start:    p.bpfObjects.UprobeProtocolRoundtrip,
			End:      p.bpfObjects.UprobeProtocolRoundtripRet,
			Required: true,
		},
		"github.com/segmentio/kafka-go.(*reader).read": { // used for capturing the info for the fetch operations
			Start:    p.bpfObjects.UprobeReaderRead,
			End:      p.bpfObjects.UprobeReaderReadRet,
			Required: true,
		},
		"github.com/segmentio/kafka-go.(*reader).sendMessage": { // to accurately measure the start time
			Start:    p.bpfObjects.UprobeReaderRead,
			Required: true,
		},
	}
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
