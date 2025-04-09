package logger

import (
	//"bytes"
	"context"
	//"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/config"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/ringbuf"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_info_t -target amd64,arm64 bpf_debug ../../../../bpf/logger/logger.c -- -I../../../../bpf -DBPF_DEBUG

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


func bytesToLogInfo(b []byte) (*BPFLogInfo, error) {
	if len(b) < int(unsafe.Sizeof(BPFLogInfo{})) {
		return nil, fmt.Errorf("byte slice too short")
	}

	return (*BPFLogInfo)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&b)).Data)), nil
}

func (p *BPFLogger) processLogEvent(_ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	event, err := bytesToLogInfo(record.RawSample)

	if err == nil {
		p.log.Debug(readString(event.Log[:]), "pid", event.Pid, "comm", readString(event.Comm[:]))
	}

	return request.Span{}, true, nil
}

func readString(data []int8) string {
	/*
	bytes := make([]byte, len(data))
	for i, v := range data {
		if v == 0 { // null-terminated string
			bytes = bytes[:i]
			break
		}
		bytes[i] = byte(v)
	}
	return string(bytes)
	*/

	return *(*string)(unsafe.Pointer(&data))
}
