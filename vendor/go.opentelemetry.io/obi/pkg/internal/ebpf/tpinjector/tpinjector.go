// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"context"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/tpinjector/tpinjector.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfDebug ../../../../bpf/tpinjector/tpinjector.c -- -I../../../../bpf -I../../../../bpf -DBPF_DEBUG -DBPF_DEBUG_TC

type Tracer struct {
	cfg        *obi.Config
	bpfObjects BpfObjects
	closers    []io.Closer
	log        *slog.Logger
}

func New(cfg *obi.Config) *Tracer {
	log := slog.With("component", "tpinjector")

	return &Tracer{
		log: log,
		cfg: cfg,
	}
}

func (p *Tracer) AllowPID(uint32, uint32, *svc.Attrs) {}

func (p *Tracer) BlockPID(uint32, uint32) {}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	if p.cfg.EBPF.BpfDebug {
		return LoadBpfDebug()
	}

	return LoadBpf()
}

func (p *Tracer) SetupTailCalls() {
	for _, tc := range []struct {
		index int
		prog  *ebpf.Program
	}{
		{
			index: 0,
			prog:  p.bpfObjects.ObiPacketExtenderWriteMsgTp,
		},
	} {
		err := p.bpfObjects.ExtenderJumpTable.Update(uint32(tc.index), uint32(tc.prog.FD()), ebpf.UpdateAny)
		if err != nil {
			p.log.Error("error loading info tail call jump table", "error", err)
		}
	}
}

func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 3)

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	// This must match httpfltr.go, otherwise we get partial events in userspace.
	if p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(0)
	} else {
		m["filter_pids"] = int32(1)
	}

	m["max_transaction_time"] = uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds())

	// Set injection flags based on context propagation configuration
	flags := uint32(0)
	if p.cfg.EBPF.ContextPropagation.HasHeaders() {
		flags |= 1 // k_inject_http_headers
	}
	if p.cfg.EBPF.ContextPropagation.HasTCP() {
		flags |= 2 // k_inject_tcp_options
	}
	m["inject_flags"] = flags

	return m
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return []ebpfcommon.SockMsg{
		{
			Program:  p.bpfObjects.ObiPacketExtender,
			MapFD:    p.bpfObjects.SockDir.FD(),
			AttachAs: ebpf.AttachSkMsgVerdict,
		},
	}
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return []ebpfcommon.SockOps{
		{
			Program:  p.bpfObjects.ObiSockmapTracker,
			AttachAs: ebpf.AttachCGroupSockOps,
		},
	}
}

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("tpinjector started")

	<-ctx.Done()

	p.bpfObjects.Close()

	p.log.Debug("tpinjector terminated")
}

func (p *Tracer) Required() bool {
	return false
}
