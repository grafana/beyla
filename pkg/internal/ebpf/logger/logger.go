package logger

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/request"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_info_t -target amd64,arm64 bpf_debug ../../../../bpf/debug_log.c -- -I../../../../bpf/headers -DBPF_DEBUG

type BPFLogInfo bpf_debugLogInfoT

type BPFLogger struct {
	cfg        *beyla.Config
	bpfObjects bpf_debugObjects
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
		return loadBpf_debug()
	}
	return nil, errors.New("BPF debug is not enabled")
}

func (p *BPFLogger) BpfObjects() any {
	return &p.bpfObjects
}

func (p *BPFLogger) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *BPFLogger) KProbes() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *BPFLogger) Tracepoints() map[string]ebpfcommon.FunctionPrograms {
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

func (p *BPFLogger) processLogEvent(record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	var event BPFLogInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)

	if err == nil {
		p.log.Debug(readString(event.Log[:]), "pid", event.Pid, "comm", readString(event.Comm[:]))
	}

	return request.Span{}, true, nil
}

func readString(data []int8) string {
	bytes := make([]byte, len(data))
	for i, v := range data {
		if v == 0 { // null-terminated string
			bytes = bytes[:i]
			break
		}
		bytes[i] = byte(v)
	}
	return string(bytes)
}
