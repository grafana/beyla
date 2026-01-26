// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher // import "go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/shardedqueue"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_event_t -target amd64,arm64 Bpf ../../../../bpf/logenricher/logenricher.c -- -I../../../../bpf -I../../../../bpf

type LogEvent struct {
	orig    BpfLogEventT
	logLine string
}

type Tracer struct {
	ctx         context.Context
	cfg         *obi.Config
	bpfObjects  BpfObjects
	closers     []io.Closer
	log         *slog.Logger
	fdCache     *expirable.LRU[string, *os.File]
	asyncWriter *shardedqueue.ShardedQueue[LogEvent]
	pids        map[uint32][]uint32 // ns:[]pid
	pidsMU      sync.Mutex
}

func New(cfg *obi.Config) *Tracer {
	logger := slog.With("component", "logenricher")

	if !ebpfcommon.SupportsLogInjection(logger) {
		logger.Warn("log enrichment not supported on this system!")
		return nil
	}

	tr := &Tracer{
		log: logger,
		cfg: cfg,
		fdCache: expirable.NewLRU[string, *os.File](cfg.EBPF.LogEnricher.CacheSize, func(_ string, f *os.File) {
			f.Close()
		}, cfg.EBPF.LogEnricher.CacheTTL),
		pids: make(map[uint32][]uint32),
	}

	asyncWriter := shardedqueue.NewShardedQueue[LogEvent](
		cfg.EBPF.LogEnricher.AsyncWriterWorkers,
		cfg.EBPF.LogEnricher.AsyncWriterChannelLen,
		func(e LogEvent) string { return e.filePath() },
		func(_ int, ch <-chan LogEvent) {
			for e := range ch {
				tr.handle(e)
			}
		},
	)

	tr.asyncWriter = asyncWriter

	return tr
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	return LoadBpf()
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) Constants() map[string]any {
	return map[string]any{
		"g_bpf_debug": p.cfg.EBPF.BpfDebug,
	}
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
	m := map[string]ebpfcommon.ProbeDesc{
		"tty_write": {
			Start:    p.bpfObjects.ObiKprobeTtyWrite,
			Required: true,
		},
		"ksys_write": {
			Start:    p.bpfObjects.ObiKprobeKsysWrite,
			Required: true,
		},
	}

	hasPipeWrite, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymPipeWrite)
	if err != nil {
		p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymPipeWrite, "error", err)
	}

	if hasPipeWrite {
		m["pipe_write"] = ebpfcommon.ProbeDesc{
			Start:    p.bpfObjects.ObiKprobePipeWrite,
			Required: true,
		}
	} else {
		hasAnonPipeWrite, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymAnonPipeWrite)
		if err != nil {
			p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymAnonPipeWrite, "error", err)
		}

		if hasAnonPipeWrite {
			m["anon_pipe_write"] = ebpfcommon.ProbeDesc{
				Start:    p.bpfObjects.ObiKprobePipeWrite,
				Required: true,
			}
		} else {
			p.log.Error("neither anon_pipe_write nor pipe_write kernel symbols are available; log enrichment may not work correctly")
		}
	}

	return m
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
	return nil
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return nil
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

func (p *Tracer) pidKey(nsid, pid uint32) uint64 {
	return (uint64(nsid) << 32) | uint64(pid)
}

func (p *Tracer) addPID(key uint64) error {
	p.log.Debug("adding pid", "pid", uint32(key), "ns", key>>32)
	if err := p.bpfObjects.LogEnricherPids.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("error adding pid %d (ns=%d) to bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) removePID(key uint64) error {
	p.log.Debug("removing pid", "pid", uint32(key), "ns", key>>32)
	if err := p.bpfObjects.LogEnricherPids.Delete(key); err != nil {
		return fmt.Errorf("error removing pid %d (ns=%d) from bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) AllowPID(pid, ns uint32, _ *svc.Attrs) {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	if err := p.addPID(p.pidKey(ns, pid)); err != nil {
		p.log.Error(err.Error())
	}

	nsPids, err := procs.FindNamespacedPids(int32(pid))
	if err != nil {
		p.log.Error("allow pid: error finding namespaced pids", "error", err)
		return
	}

	for _, nsPid := range nsPids {
		if err := p.addPID(p.pidKey(ns, nsPid)); err != nil {
			p.log.Error(err.Error())
		}
	}

	nsPids = append(nsPids, pid)

	p.pids[pid] = nsPids
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	if err := p.removePID(p.pidKey(ns, pid)); err != nil {
		p.log.Error(err.Error())
	}

	if knownPids, ok := p.pids[pid]; ok {
		for _, nsPid := range knownPids {
			if err := p.removePID(p.pidKey(ns, nsPid)); err != nil {
				p.log.Error(err.Error())
			}
		}
		return
	}

	p.log.Debug("block pid: namespaced pids not found in internal cache, removing only the given pid", "pid", pid, "ns", ns)
}

func (p *Tracer) Run(ctx context.Context, eventCtx *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("starting")

	p.ctx = ctx

	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.LogEvents,
		eventCtx.CommonPIDsFilter,
		p.handleLogEvent,
		p.log,
		nil,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)

	p.log.Debug("terminating")
}

func (p *Tracer) Required() bool {
	return false
}

func (p *Tracer) handleLogEvent(_ *ebpfcommon.EBPFParseContext, _ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	hdrSize := uint32(unsafe.Sizeof(BpfLogEventT{})) - uint32(unsafe.Sizeof(uintptr(0))) // Remove `log` placeholder

	event, err := ebpfcommon.ReinterpretCast[BpfLogEventT](record.RawSample)
	if err != nil {
		// This should never happen -- if it does, we can't really recover
		// and the targeted process will miss his logs.
		return request.Span{}, true, nil
	}

	err = p.asyncWriter.Enqueue(p.ctx, LogEvent{
		orig:    *event,
		logLine: unix.ByteSliceToString(record.RawSample[hdrSize : hdrSize+event.Len]),
	})
	return request.Span{}, true, err
}

func (e LogEvent) filePath() string {
	var fp string

	procFdPath := func(fd int) string {
		return filepath.Join("/proc", strconv.FormatUint(uint64(e.orig.Tgid), 10), "fd", strconv.Itoa(fd))
	}

	if e.orig.Fd != 0 {
		// This is a pipe write, use the target process pipe fd
		fp = procFdPath(int(e.orig.Fd))
	} else {
		// TTY write
		fp = unix.ByteSliceToString(e.orig.FilePath[:])
		if fp == "" {
			// Fallback to process stdout in the case path resolver failed
			fp = procFdPath(1)
		}
	}

	return fp
}

func (p *Tracer) handle(e LogEvent) {
	// Get or open the file descriptor
	f, ok := p.fdCache.Get(e.filePath())
	if !ok {
		f2, err2 := os.OpenFile(e.filePath(), os.O_WRONLY|os.O_APPEND, 0)
		if err2 != nil {
			p.log.Error("failed to open log file for writing", "path", e.filePath(), "error", err2)
			return
		}
		p.fdCache.Add(e.filePath(), f2)
		f = f2
	}

	var (
		zeroTraceID [16]uint8
		zeroSpanID  [8]uint8
	)
	if e.orig.PidTp.Tp.TraceId == zeroTraceID || e.orig.PidTp.Tp.SpanId == zeroSpanID {
		// No trace context to inject, write original log line
		_, err := f.Write([]byte(e.logLine))
		if err != nil {
			p.log.Error("failed to write log line", "error", err)
		}
		return
	}

	var (
		b       bytes.Buffer
		spanID  = trace.SpanID(e.orig.PidTp.Tp.SpanId)
		traceID = trace.TraceID(e.orig.PidTp.Tp.TraceId)
	)

	var m map[string]any
	if err := json.Unmarshal([]byte(e.logLine), &m); err == nil {
		// JSON -> enrich with context
		m["trace_id"] = traceID.String()
		m["span_id"] = spanID.String()

		out, err2 := json.Marshal(m)
		if err2 != nil {
			p.log.Warn("failed to marshal enriched log line, writing original", "error", err2)
			b.Write([]byte(e.logLine))
			return
		}

		b.Write(out)
		b.WriteByte('\n')
	} else {
		// Not JSON -> preserve the original logline
		b.Write([]byte(e.logLine[:e.orig.Len]))
	}

	_, err := f.Write(b.Bytes())
	if err != nil {
		p.log.Error("failed to write enriched log line", "error", err)
	}
}
