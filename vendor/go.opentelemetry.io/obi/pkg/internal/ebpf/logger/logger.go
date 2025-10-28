// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/obi"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_info_t -target amd64,arm64 BpfDebug ../../../../bpf/logger/logger.c -- -I../../../../bpf -DBPF_DEBUG

type BPFLogInfo BpfDebugLogInfoT

type BPFLogger struct {
	cfg        *obi.Config
	bpfObjects BpfDebugObjects
	closers    []io.Closer
	log        *slog.Logger
}

type Event struct {
	Log string
}

func New(cfg *obi.Config) *BPFLogger {
	log := slog.With("component", "BPFLogger")
	return &BPFLogger{
		log: log,
		cfg: cfg,
	}
}

func (p *BPFLogger) Load() (*ebpf.CollectionSpec, error) {
	if p.cfg.EBPF.BpfDebug {
		return LoadBpfDebug()
	}
	return nil, errors.New("BPF debug is not enabled")
}

func (p *BPFLogger) BpfObjects() any {
	return &p.bpfObjects
}

func (p *BPFLogger) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *BPFLogger) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *BPFLogger) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *BPFLogger) SetupTailCalls() {}

func (p *BPFLogger) Run(ctx context.Context) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.DebugEvents,
		&ebpfcommon.IdentityPidsFilter{},
		p.processLogEvent,
		p.log,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)
}

func (p *BPFLogger) processLogEvent(_ *ebpfcommon.EBPFParseContext, _ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[BPFLogInfo](record.RawSample)

	if err == nil {
		p.log.Debug(unix.ByteSliceToString(event.Log[:]), "pid", event.Pid, "comm", unix.ByteSliceToString(event.Comm[:]))
	}

	return request.Span{}, true, nil
}
