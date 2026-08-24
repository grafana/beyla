// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher // import "go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/shardedqueue"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_event_t -type log_pipe_key_t -target amd64,arm64 Bpf ../../../../bpf/logenricher/logenricher.c -- -I../../../../bpf -I../../../../bpf

type LogEvent struct {
	orig    BpfLogEventT
	logLine string
	dest    string
	out     *destFile // reference owned by this event until its write completes
}

// destFile is a refcounted open log destination: the fd cache holds one
// reference and every in-flight event holds another, so retiring a pipe or
// evicting the cache entry cannot close a descriptor a queued write still
// needs
type destFile struct {
	f    *os.File
	refs atomic.Int64
}

// tryAcquire takes a reference unless the descriptor already closed
func (d *destFile) tryAcquire() bool {
	for {
		n := d.refs.Load()
		if n <= 0 {
			return false
		}
		if d.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (d *destFile) release() {
	if d.refs.Add(-1) == 0 {
		d.f.Close()
	}
}

// pipe identity as the BPF map sees it: inode number plus the kernel dev_t of
// its superblock, since bare inode numbers collide across filesystems
type pipeKey = BpfLogPipeKeyT

type Tracer struct {
	ctx         context.Context
	cfg         *obi.Config
	bpfObjects  BpfObjects
	closers     []io.Closer
	log         *slog.Logger
	fdCache     *expirable.LRU[string, *destFile]
	asyncWriter *shardedqueue.ShardedQueue[LogEvent]
	formatter   logFormatter
	pids        map[uint64][]uint64       // pid:[]nsPids
	pidServices map[uint32]*exec.FileInfo // host pid -> file info, for run-time OTel-export check in handle()
	pidsMU      sync.Mutex
	trackedPids map[uint32]struct{}          // host pids currently allowed
	logPipes    map[pipeKey]map[uint32][]int // log pipe -> host pid -> fds (1 and/or 2)
	pidPipes    map[uint32]map[int]pipeKey   // host pid -> fd -> registered log pipe
	pipesMU     sync.RWMutex                 // guards trackedPids, logPipes, pidPipes; hot-path readers vs reconcile
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
		fdCache: expirable.NewLRU[string, *destFile](cfg.EBPF.LogEnricher.CacheSize, func(_ string, d *destFile) {
			d.release()
		}, cfg.EBPF.LogEnricher.CacheTTL),
		formatter:   newLogFormatter(cfg.EBPF.LogEnricher),
		pids:        make(map[uint64][]uint64),
		pidServices: make(map[uint32]*exec.FileInfo),
		trackedPids: make(map[uint32]struct{}),
		logPipes:    make(map[pipeKey]map[uint32][]int),
		pidPipes:    make(map[uint32]map[int]pipeKey),
	}

	asyncWriter := shardedqueue.NewShardedQueue[LogEvent](
		cfg.EBPF.LogEnricher.AsyncWriterWorkers,
		cfg.EBPF.LogEnricher.AsyncWriterChannelLen,
		func(e LogEvent) string { return e.shardKey() },
		func(_ int, ch <-chan LogEvent) {
			for e := range ch {
				tr.handle(e)
			}
		},
	)

	tr.asyncWriter = asyncWriter

	return tr
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}
	return []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}, nil
}

func (p *Tracer) constants() map[string]any {
	return map[string]any{"g_bpf_debug": p.cfg.EBPF.BpfDebug}
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

	hasDoWritev, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymDoWritev)
	if err != nil {
		p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymDoWritev, "error", err)
	}

	if hasDoWritev {
		m["do_writev"] = ebpfcommon.ProbeDesc{
			Start:    p.bpfObjects.ObiKprobeDoWritev,
			Required: false,
		}
	} else {
		p.log.Warn("do_writev kernel symbol not available; writev()-based log writes won't be enriched")
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

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
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

func (p *Tracer) Tracing() []*ebpfcommon.Tracing { return nil }

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) pidKey(nsid, pid uint32) uint64 {
	return (uint64(nsid) << 32) | uint64(pid)
}

func (p *Tracer) shouldOmitSpanID(hostPID uint32) bool {
	if !p.cfg.Discovery.ExcludeOTelInstrumentedServices {
		return false
	}

	p.pidsMU.Lock()
	s := p.pidServices[hostPID]
	p.pidsMU.Unlock()

	return s != nil && s.ExportsOTelTraces()
}

func (p *Tracer) addPID(key uint64) error {
	p.log.Debug("adding pid", "pid", uint32(key), "ns", key>>32)
	if p.bpfObjects.LogEnricherPids == nil {
		return fmt.Errorf("BPF objects not loaded, cannot add pid %d (ns=%d)", uint32(key), key>>32)
	}
	if err := p.bpfObjects.LogEnricherPids.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("error adding pid %d (ns=%d) to bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) removePID(key uint64) error {
	p.log.Debug("removing pid", "pid", uint32(key), "ns", key>>32)
	if p.bpfObjects.LogEnricherPids == nil {
		return fmt.Errorf("BPF objects not loaded, cannot remove pid %d (ns=%d)", uint32(key), key>>32)
	}
	if err := p.bpfObjects.LogEnricherPids.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("error removing pid %d (ns=%d) from bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo) {
	p.pipesMU.Lock()
	p.trackedPids[uint32(pid)] = struct{}{}
	p.pipesMU.Unlock()
	p.registerLogPipes(uint32(pid))

	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	if fi != nil {
		p.pidServices[uint32(pid)] = fi
	}

	pk := p.pidKey(ns, uint32(pid))
	if err := p.addPID(pk); err != nil {
		p.log.Error(err.Error())
	}

	nsPids, err := procs.FindNamespacedPids(pid)
	if err != nil {
		// short-lived processes routinely exit before discovery allows them
		if errors.Is(err, os.ErrNotExist) {
			p.log.Debug("allow pid: process gone before namespaced pid lookup", "pid", pid, "error", err)
		} else {
			p.log.Error("allow pid: error finding namespaced pids", "error", err)
		}
		return
	}

	for _, nsPid := range nsPids {
		if pid == nsPid {
			continue
		}

		nsPk := p.pidKey(ns, uint32(nsPid))
		if err := p.addPID(nsPk); err != nil {
			p.log.Error(err.Error())
		}
		p.pids[pk] = append(p.pids[pk], nsPk)
	}
}

// userspace stat encodes dev_t differently from the kernel s_dev the BPF
// program reads; undo the stat encoding so both sides agree on the key
func kernelDev(dev uint64) uint64 {
	return uint64(unix.Major(dev))<<20 | uint64(unix.Minor(dev))
}

// pipe identity behind /proc/<pid>/fd/<fd>, zero when gone or not a pipe
func statPipeKey(pid uint32, fd int) pipeKey {
	var st unix.Stat_t
	if err := unix.Stat(procFdPath(pid, fd), &st); err != nil {
		return pipeKey{}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return pipeKey{}
	}

	return pipeKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}
}

// registerLogPipes records the pipes currently behind stdout/stderr, retiring
// registrations the process redirected away from. The stats run unlocked so
// slow /proc access never stalls the event hot path
func (p *Tracer) registerLogPipes(pid uint32) {
	var desired [2]pipeKey
	for i, fd := range []int{1, 2} {
		desired[i] = statPipeKey(pid, fd)
	}

	p.pipesMU.Lock()
	defer p.pipesMU.Unlock()

	// the pid may have been blocked while stating; registering would leak
	if _, ok := p.trackedPids[pid]; !ok {
		return
	}

	for i, fd := range []int{1, 2} {
		key := desired[i]
		current := p.pidPipes[pid][fd]
		if current == key {
			continue
		}

		if current != (pipeKey{}) {
			p.removePipeFD(pid, fd, current)
		}
		if key != (pipeKey{}) {
			p.addPipeFD(pid, fd, key)
		}
	}
}

// callers must hold pipesMU. On BPF update failure nothing is recorded, so
// the next reconcile retries instead of leaving the pipe silently unenriched
func (p *Tracer) addPipeFD(pid uint32, fd int, key pipeKey) {
	owners := p.logPipes[key]
	if owners == nil {
		if p.bpfObjects.LogPipes == nil {
			p.log.Error("BPF objects not loaded, cannot register log pipe", "ino", key.Ino, "dev", key.Dev)
			return
		}
		if err := p.bpfObjects.LogPipes.Put(key, uint8(1)); err != nil {
			p.log.Error("error registering log pipe in bpf map", "ino", key.Ino, "dev", key.Dev, "error", err)
			return
		}
		owners = make(map[uint32][]int)
		p.logPipes[key] = owners
	}
	owners[pid] = append(owners[pid], fd)

	if p.pidPipes[pid] == nil {
		p.pidPipes[pid] = make(map[int]pipeKey)
	}
	p.pidPipes[pid][fd] = key
}

// callers must hold pipesMU
func (p *Tracer) removePipeFD(pid uint32, fd int, key pipeKey) {
	delete(p.pidPipes[pid], fd)
	// a held write end would rob readers of EOF once the fd is gone
	p.fdCache.Remove(procFdPath(pid, fd))

	owners := p.logPipes[key]
	if fds, ok := owners[pid]; ok {
		fds = slices.DeleteFunc(fds, func(f int) bool { return f == fd })
		if len(fds) > 0 {
			owners[pid] = fds
		} else {
			delete(owners, pid)
		}
	}
	if len(owners) > 0 {
		return
	}

	delete(p.logPipes, key)

	if p.bpfObjects.LogPipes == nil {
		return
	}
	if err := p.bpfObjects.LogPipes.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		p.log.Error("error removing log pipe from bpf map", "ino", key.Ino, "dev", key.Dev, "error", err)
	}
}

// callers must hold pipesMU
func (p *Tracer) unregisterLogPipes(pid uint32) {
	for fd, key := range p.pidPipes[pid] {
		p.removePipeFD(pid, fd, key)
	}

	delete(p.pidPipes, pid)
}

// processes may redirect their stdio after discovery; re-stat and diff so new
// pipes get enriched, stale registrations and fd handles are retired, and
// failed BPF registrations are retried
func (p *Tracer) reconcileLogPipes() {
	p.pipesMU.RLock()
	pids := make([]uint32, 0, len(p.trackedPids))
	for pid := range p.trackedPids {
		pids = append(pids, pid)
	}
	p.pipesMU.RUnlock()

	for _, pid := range pids {
		p.registerLogPipes(pid)
	}
}

func (p *Tracer) pipeDestCandidates(key pipeKey) []string {
	p.pipesMU.RLock()
	defer p.pipesMU.RUnlock()

	owners := p.logPipes[key]

	pids := make([]uint32, 0, len(owners))
	for pid := range owners {
		pids = append(pids, pid)
	}
	slices.Sort(pids)

	var paths []string
	for _, pid := range pids {
		for _, fd := range owners[pid] {
			paths = append(paths, procFdPath(pid, fd))
		}
	}

	return paths
}

func (p *Tracer) pipeRegistered(key pipeKey) bool {
	p.pipesMU.RLock()
	defer p.pipesMU.RUnlock()

	_, ok := p.logPipes[key]
	return ok
}

// identity to pin the tty fallback destination with; rejects an unregistered
// pipe (app IPC)
func (p *Tracer) fallbackDest(path string) (pipeKey, bool, bool) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return pipeKey{}, false, false
	}

	key := pipeKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}
	isPipe := st.Mode&unix.S_IFMT == unix.S_IFIFO
	if isPipe && !p.pipeRegistered(key) {
		return pipeKey{}, false, false
	}

	return key, isPipe, true
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32) {
	p.pipesMU.Lock()
	delete(p.trackedPids, uint32(pid))
	p.unregisterLogPipes(uint32(pid))
	p.pipesMU.Unlock()

	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	delete(p.pidServices, uint32(pid))

	pk := p.pidKey(ns, uint32(pid))
	if err := p.removePID(pk); err != nil {
		p.log.Error(err.Error())
	}

	if knownPids, ok := p.pids[pk]; ok {
		for _, nsPk := range knownPids {
			if err := p.removePID(nsPk); err != nil {
				p.log.Error(err.Error())
			}
		}
		delete(p.pids, pk)
		return
	}

	p.log.Debug("block pid: namespaced pids not found in internal cache, removing only the given pid", "pid", pid, "ns", ns)
}

const logPipeReconcileInterval = 15 * time.Second

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("starting")

	p.ctx = ctx

	go func() {
		t := time.NewTicker(logPipeReconcileInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.reconcileLogPipes()
			}
		}
	}()

	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.LogEvents,
		p.handleLogEvent,
		nil,
		p.log,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)

	p.log.Debug("terminating")
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return false
}

func (p *Tracer) handleLogEvent(record *ringbuf.Record) (request.Span, bool, error) {
	hdrSize := uint32(unsafe.Offsetof(BpfLogEventT{}.Log)) // Remove `log` placeholder

	event, err := ebpfcommon.ReinterpretCast[BpfLogEventT](record.RawSample)
	if err != nil {
		// This should never happen -- if it does, we can't really recover
		// and the targeted process will miss his logs.
		return request.Span{}, true, nil
	}

	e := LogEvent{
		orig:    *event,
		logLine: unix.ByteSliceToString(record.RawSample[hdrSize : hdrSize+event.Len]),
	}

	// Open the destination now, while the writing process is still alive: the
	// event's reference keeps the descriptor open even if the process exits
	// and its registration is retired before the async writer gets to this
	// line.
	if event.Fd != 0 {
		key := pipeKey{Ino: event.Ino, Dev: uint64(event.Dev)}
		// address the pipe through a live owner, the writer may already be gone
		for _, candidate := range p.pipeDestCandidates(key) {
			if d, err := p.openPipeDestination(candidate, key); err == nil {
				e.dest = candidate
				e.out = d
				break
			}
		}
		if e.out == nil {
			p.log.Debug("no live destination for log pipe, dropping line", "ino", event.Ino, "dev", event.Dev)
			return request.Span{}, true, nil
		}
	} else {
		e.dest = e.ttyPath()
		var (
			pin      pipeKey
			pipeDest bool
		)
		if unix.ByteSliceToString(event.FilePath[:]) == "" {
			var ok bool
			if pin, pipeDest, ok = p.fallbackDest(e.dest); !ok {
				p.log.Debug("unsafe tty fallback destination, dropping line", "path", e.dest)
				return request.Span{}, true, nil
			}
		}
		var d *destFile
		if pipeDest {
			d, err = p.openPipeDestination(e.dest, pin)
		} else {
			d, err = p.openLogDestination(e.dest, pin)
		}
		if err != nil {
			p.logOpenError(e.dest, err)
			return request.Span{}, true, nil
		}
		e.out = d
	}

	if err := p.asyncWriter.Enqueue(p.ctx, e); err != nil {
		e.out.release()
		return request.Span{}, true, err
	}
	return request.Span{}, true, nil
}

var errStaleDestination = errors.New("destination no longer points at the captured pipe")

func fileKey(f *os.File) pipeKey {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return pipeKey{}
	}

	return pipeKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}
}

// O_NONBLOCK so a reader-less pipe fails the open with ENXIO instead of
// blocking the event handler forever; writes revert to blocking so a full
// pipe backpressures its shard instead of dropping lines
func openDestFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err == nil {
		_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	}
	if err != nil {
		unix.Close(fd)
		return nil, &os.PathError{Op: "fcntl", Path: path, Err: err}
	}

	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: path, Err: unix.EBADF}
	}

	return f, nil
}

// callers must hold pipesMU
func (p *Tracer) pipeDestinationRegisteredLocked(path string, key pipeKey) bool {
	owners := p.logPipes[key]
	for pid, fds := range owners {
		for _, fd := range fds {
			if procFdPath(pid, fd) == path {
				return true
			}
		}
	}

	return false
}

func (p *Tracer) cacheDestination(path string, d *destFile) {
	d.refs.Add(1)
	// Add on a lingering expired entry replaces it without the evict
	// callback, which would leak its cache reference; Remove fires it
	p.fdCache.Remove(path)
	p.fdCache.Add(path, d)
}

func (p *Tracer) cachePipeDestination(path string, key pipeKey, d *destFile) {
	p.pipesMU.RLock()
	defer p.pipesMU.RUnlock()

	if p.pipeDestinationRegisteredLocked(path, key) {
		p.cacheDestination(path, d)
	}
}

// a non-zero pin fixes the destination identity: /proc fd paths re-point when
// the owner redirects its stdio, and writing there would leak lines into the
// wrong file. The returned reference is owned by the caller and must be
// released once the write completes
func (p *Tracer) openDestination(path string, pin pipeKey, pipeDest bool) (*destFile, error) {
	if d, ok := p.fdCache.Get(path); ok {
		if (pin == (pipeKey{}) || fileKey(d.f) == pin) && d.tryAcquire() {
			return d, nil
		}
		p.fdCache.Remove(path)
	}

	f, err := openDestFile(path)
	if err != nil {
		return nil, err
	}
	if pin != (pipeKey{}) && fileKey(f) != pin {
		f.Close()
		return nil, errStaleDestination
	}

	d := &destFile{f: f}
	d.refs.Store(1) // caller reference
	if pipeDest {
		// Serialize publication with pipe retirement. If the owner retired while
		// the destination was opening, the event reference still delivers the
		// captured line without resurrecting a stale cache writer.
		p.cachePipeDestination(path, pin, d)
	} else {
		p.cacheDestination(path, d)
	}

	return d, nil
}

func (p *Tracer) openLogDestination(path string, pin pipeKey) (*destFile, error) {
	return p.openDestination(path, pin, false)
}

func (p *Tracer) openPipeDestination(path string, pin pipeKey) (*destFile, error) {
	return p.openDestination(path, pin, true)
}

// a gone, re-pointed, or reader-less destination means its process died or
// redirected between writing the line and us getting to it: expected, drop
// quietly
func (p *Tracer) logOpenError(path string, err error) {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, errStaleDestination) || errors.Is(err, unix.ENXIO) {
		p.log.Debug("log destination is gone, dropping line", "path", path, "error", err)
		return
	}

	p.log.Error("failed to open log file for writing", "path", path, "error", err)
}

func procFdPath(pid uint32, fd int) string {
	return filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "fd", strconv.Itoa(fd))
}

func (e LogEvent) ttyPath() string {
	fp := unix.ByteSliceToString(e.orig.FilePath[:])
	if fp == "" {
		// Fallback to process stdout in the case path resolver failed
		fp = procFdPath(e.orig.Tgid, 1)
	}

	return fp
}

// pipe lines shard by pipe identity so a changing candidate path cannot move
// a pipe's lines across shards and reorder them; tty lines shard by path
func (e LogEvent) shardKey() string {
	if e.orig.Fd != 0 {
		return "pipe:" + strconv.FormatUint(uint64(e.orig.Dev), 10) + ":" + strconv.FormatUint(e.orig.Ino, 10)
	}

	return e.dest
}

func (p *Tracer) handle(e LogEvent) {
	// the event owns a reference taken at capture time, so the destination is
	// alive here even if its owner exited or the cache evicted it meanwhile
	defer e.out.release()
	f := e.out.f

	var (
		zeroTraceID [16]uint8
		zeroSpanID  [8]uint8
	)
	if e.orig.Ctx.TraceId == zeroTraceID || e.orig.Ctx.SpanId == zeroSpanID {
		// No trace context to inject, write original log line
		_, err := f.Write([]byte(e.logLine))
		if err != nil {
			p.log.Error("failed to write log line", "error", err)
		}
		return
	}

	spanID := trace.SpanID(e.orig.Ctx.SpanId)
	traceID := trace.TraceID(e.orig.Ctx.TraceId)
	includeSpan := !p.shouldOmitSpanID(e.orig.Tgid)

	out, err := p.formatter.format([]byte(e.logLine), traceID.String(), spanID.String(), includeSpan)
	if err != nil {
		p.log.Warn("failed to format enriched log line, writing original", "error", err)
		out = []byte(e.logLine)
	}

	_, err = f.Write(out)
	if err != nil {
		p.log.Error("failed to write enriched log line", "error", err)
	}
}
