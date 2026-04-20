// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"context"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/tpinjector/tpinjector.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfIter ../../../../bpf/tpinjector/sock_iter.c -- -I../../../../bpf -I../../../../bpf

type Tracer struct {
	cfg            *obi.Config
	bpfObjects     BpfObjects
	bpfIterObjects BpfIterObjects
	closers        []io.Closer
	log            *slog.Logger
	iters          []*ebpfcommon.Iter
}

func New(cfg *obi.Config) *Tracer {
	log := slog.With("component", "tpinjector")

	return &Tracer{
		log: log,
		cfg: cfg,
	}
}

func (p *Tracer) AllowPID(app.PID, uint32, *svc.Attrs) {}

func (p *Tracer) BlockPID(app.PID, uint32) {}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}

	iterSpec, err := LoadBpfIter()
	if err != nil {
		return nil, err
	}

	return []*ebpfcommon.SpecBundle{
		{
			Spec:      spec,
			Objects:   &p.bpfObjects,
			Constants: p.constants(),
		},
		{
			Spec:      iterSpec,
			Objects:   &p.bpfIterObjects,
			Constants: p.iterConstants(),
		},
	}, nil
}

func (p *Tracer) constants() map[string]any {
	flags := uint32(0)
	if p.cfg.EBPF.ContextPropagation.HasHeaders() {
		flags |= 1 // k_inject_http_headers
	}
	if p.cfg.EBPF.ContextPropagation.HasTCP() {
		flags |= 2 // k_inject_tcp_options
	}

	filterPids := int32(1)
	if p.cfg.Discovery.BPFPidFilterOff {
		filterPids = 0
	}

	return map[string]any{
		"filter_pids":          filterPids,
		"max_transaction_time": uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds()),
		"inject_flags":         flags,
		"g_bpf_debug":          p.cfg.EBPF.BpfDebug,
	}
}

func (p *Tracer) iterConstants() map[string]any {
	return map[string]any{
		"g_bpf_debug": p.cfg.EBPF.BpfDebug,
	}
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

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
	if p.iters != nil {
		return p.iters
	}

	major, minor := ebpfcommon.KernelVersion()

	if major < 6 || (major == 6 && minor < 4) {
		p.log.Warn("TCP socket iterator disabled: kernel versions < 6.4 have a locking bug " +
			"in iter/tcp + sockhash that can cause an RCU stall and kernel panic. " +
			"Existing connections at startup will not be tracked for context propagation.")
		p.iters = []*ebpfcommon.Iter{}
		return p.iters
	}

	p.iters = []*ebpfcommon.Iter{{Program: p.bpfIterObjects.ObiSkIterTcp}}

	return p.iters
}

func (p *Tracer) Tracing() []*ebpfcommon.Tracing {
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

	for _, it := range p.Iters() {
		if err := it.Run(p.log); err != nil {
			p.log.Error("error running iterator", "error", err)
		}
	}

	<-ctx.Done()

	p.bpfObjects.Close()
	p.bpfIterObjects.Close()

	p.log.Debug("tpinjector terminated")
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return false
}
