// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// this file is emptied on purpose to allow Beyla compiling in non-linux environments

package tctracer

import (
	"context"
	"io"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type Tracer struct{}

func New(_ *obi.Config) *Tracer                                          { return nil }
func (p *Tracer) AllowPID(_, _ uint32, _ *svc.Attrs)                     {}
func (p *Tracer) BlockPID(_, _ uint32)                                   {}
func (p *Tracer) Load() (*ebpf.CollectionSpec, error)                    { return nil, nil }
func (p *Tracer) BpfObjects() any                                        { return nil }
func (p *Tracer) AddCloser(_ ...io.Closer)                               {}
func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc           { return nil }
func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc               { return nil }
func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc { return nil }
func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc           { return nil }
func (p *Tracer) SocketFilters() []*ebpf.Program                         { return nil }
func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg                         { return nil }
func (p *Tracer) SockOps() []ebpfcommon.SockOps                          { return nil }
func (p *Tracer) Iters() []*ebpfcommon.Iter                              { return nil }
func (p *Tracer) RecordInstrumentedLib(_ uint64, _ []io.Closer)          {}
func (p *Tracer) AddInstrumentedLibRef(_ uint64)                         {}
func (p *Tracer) UnlinkInstrumentedLib(_ uint64)                         {}
func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool                   { return false }
func (p *Tracer) Run(_ context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
}
func (p *Tracer) Constants() map[string]any                           { return nil }
func (p *Tracer) SetupTailCalls()                                     {}
func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}
func (p *Tracer) ProcessBinary(_ *exec.FileInfo)                      {}
func (p *Tracer) Required() bool                                      { return false }
