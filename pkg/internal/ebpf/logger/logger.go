package logger

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/logger"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/config"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
)

// TODO: remove this file and use vendored OBI file

type BPFLogInfo logger.BpfDebugLogInfoT

type BPFLogger struct {
	cfg        *beyla.Config
	bpfObjects logger.BpfDebugObjects
	closers    []io.Closer
	log        *slog.Logger
}

type Event struct {
	Log string
}

func New(cfg *beyla.Config) *BPFLogger {
	log := slog.With("component", "BPFLogger")
	return &BPFLogger{
		log: log,
		cfg: cfg,
	}
}

func (p *BPFLogger) Load() (*ebpf.CollectionSpec, error) {
	if p.cfg.EBPF.BpfDebug {
		return logger.LoadBpfDebug()
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
		p.log.Debug(readString(event.Log[:]), "pid", event.Pid, "comm", readString(event.Comm[:]))
	}

	return request.Span{}, true, nil
}

func readString(data []uint8) string {
	l := bytes.IndexByte(data, 0)
	if l < 0 {
		l = len(data)
	}

	return (*(*string)(unsafe.Pointer(&data)))[:l]
}
