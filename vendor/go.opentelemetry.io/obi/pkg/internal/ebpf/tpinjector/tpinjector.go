// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/tpinjector/tpinjector.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfIter ../../../../bpf/tpinjector/sock_iter.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfFionreadFixup ../../../../bpf/tpinjector/fionread_fixup.c -- -I../../../../bpf -I../../../../bpf

type Tracer struct {
	cfg                     *obi.Config
	bpfObjects              BpfObjects
	bpfIterObjects          BpfIterObjects
	bpfFionreadFixupObjects BpfFionreadFixupObjects
	closers                 []io.Closer
	log                     *slog.Logger
	iters                   []*ebpfcommon.Iter
	fionreadOnce            sync.Once
	fionreadBroken          bool
	fionreadFixupEnabled    bool
	iterMu                  sync.Mutex
	itersOnce               sync.Once
	seenNetns               *lru.Cache[uint64, struct{}]
	netnsAttempts           *lru.Cache[uint64, int]
	backfillDisabled        bool
}

const (
	// netns inodes are recycled, so entries have to age out or a new namespace that lands on a
	// freed inode never gets backfilled
	seenNetnsCacheLen = 1024
	// a namespace that keeps failing is dropped, so one broken container cannot stop the
	// backfill for every other namespace on the host
	maxNetnsAttempts = 3
)

func New(cfg *obi.Config) *Tracer {
	log := slog.With("component", "tpinjector")
	seen, err := lru.New[uint64, struct{}](seenNetnsCacheLen)
	attempts, attemptsErr := lru.New[uint64, int](seenNetnsCacheLen)
	if err != nil || attemptsErr != nil {
		log.Error("cannot create netns caches, disabling socket backfill",
			"error", errors.Join(err, attemptsErr))
	}

	return &Tracer{
		log:              log,
		cfg:              cfg,
		seenNetns:        seen,
		netnsAttempts:    attempts,
		backfillDisabled: err != nil || attemptsErr != nil,
	}
}

// AllowPID backfills sock_dir with pre-existing sockets: iter/tcp only walks the opener's netns
func (p *Tracer) AllowPID(pid app.PID, _ uint32, _ *exec.FileInfo) {
	p.iterMu.Lock()
	defer p.iterMu.Unlock()

	if p.backfillDisabled {
		return
	}

	info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		p.log.Debug("netns stat failed", "pid", pid, "error", err)
		return
	}

	inode := info.Sys().(*syscall.Stat_t).Ino
	if p.seenNetns.Contains(inode) {
		return
	}

	for _, it := range p.Iters() {
		if err := netns.WithNetNS(int(pid), func() error {
			return it.Run(p.log)
		}); err != nil {
			// EPERM is permanent: report once instead of on every discovered process
			if errors.Is(err, unix.EPERM) {
				p.log.Warn("cannot enter network namespaces, likely missing CAP_SYS_ADMIN; "+
					"context propagation for connections opened before instrumentation "+
					"will not work across namespaces", "error", err)
				p.backfillDisabled = true
				return
			}
			if errors.Is(err, os.ErrNotExist) {
				p.log.Debug("process gone before backfill", "pid", pid)
				return
			}
			p.log.Error("error running iterator in netns", "pid", pid, "error", err)

			attempts, _ := p.netnsAttempts.Get(inode)
			attempts++
			p.netnsAttempts.Add(inode, attempts)
			if attempts >= maxNetnsAttempts {
				p.log.Warn("giving up on socket backfill for this network namespace",
					"ino", inode, "attempts", attempts)
				p.seenNetns.Add(inode, struct{}{})
			}
			return
		}
	}

	// reached only when every iterator ran; a failure above returns so a later pid retries
	p.netnsAttempts.Remove(inode)
	p.seenNetns.Add(inode, struct{}{})
}

func (p *Tracer) BlockPID(app.PID, uint32) {}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}

	bundles := []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}

	// BpfIter uses bpf_iter__tcp. The verifier needs bpf_iter_tcp_get_func_proto
	// to recognize the sock_iter ctx type; that landed in 5.11. Loading on older
	// kernels fails with "Unrecognized arg#0 type PTR". Iters() additionally
	// gates attach on >= 6.4 (RCU stall bug), so skipping the bundle below 5.11
	// is strictly an extension of that.
	if major, minor := ebpfcommon.KernelVersion(); major > 5 || (major == 5 && minor >= 11) {
		iterSpec, err := LoadBpfIter()
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, &ebpfcommon.SpecBundle{
			Spec:      iterSpec,
			Objects:   &p.bpfIterObjects,
			Constants: p.iterConstants(),
		})
	}

	// kernel lockdown rejects bpf_probe_write_user at load time
	if p.kernelBreaksFIONREAD() {
		fixupSpec, err := loadableFIONREADFixup()
		if err != nil {
			p.log.Error("kernel misreports FIONREAD for sockets in a sockhash and the BPF "+
				"compensation cannot be loaded (kernel lockdown?); applications sizing reads "+
				"via FIONREAD (nginx, Java, .NET) may stall or truncate transfers; "+
				"set context_propagation: disabled (OTEL_EBPF_BPF_CONTEXT_PROPAGATION=disabled) "+
				"to avoid impact", "error", err)
		} else {
			bundles = append(bundles, &ebpfcommon.SpecBundle{
				Spec:      fixupSpec,
				Objects:   &p.bpfFionreadFixupObjects,
				Constants: map[string]any{"g_bpf_debug": p.cfg.EBPF.BpfDebug},
			})
			p.fionreadFixupEnabled = true
		}
	}

	return bundles, nil
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

// Tracepoints returns the FIONREAD fixup probes; not Required so a failed
// attach cannot drop the tracer
func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	if !p.fionreadFixupEnabled {
		return nil
	}
	return map[string]ebpfcommon.ProbeDesc{
		"syscalls/sys_enter_ioctl": {Start: p.bpfFionreadFixupObjects.ObiFionreadFixupEnter},
		"syscalls/sys_exit_ioctl":  {Start: p.bpfFionreadFixupObjects.ObiFionreadFixupExit},
	}
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

// Iters is called from both AllowPID (discovery) and Run (pipeline) goroutines
func (p *Tracer) Iters() []*ebpfcommon.Iter {
	p.itersOnce.Do(func() {
		major, minor := ebpfcommon.KernelVersion()

		if major < 6 || (major == 6 && minor < 4) {
			p.log.Warn("TCP socket iterator disabled: kernel versions < 6.4 have a locking bug " +
				"in iter/tcp + sockhash that can cause an RCU stall and kernel panic. " +
				"Existing connections at startup will not be tracked for context propagation.")
			p.iters = []*ebpfcommon.Iter{}
			return
		}

		// the result is cached for the tracer's life, so refuse to cache unloaded programs
		if p.bpfIterObjects.ObiSkIterTcpListen == nil || p.bpfIterObjects.ObiSkIterTcp == nil {
			p.log.Warn("TCP socket iterators are not loaded, socket backfill disabled")
			p.iters = []*ebpfcommon.Iter{}
			return
		}

		// listening ports first, so the second pass can discard passive established sockets
		p.iters = []*ebpfcommon.Iter{
			{Program: p.bpfIterObjects.ObiSkIterTcpListen},
			{Program: p.bpfIterObjects.ObiSkIterTcp},
		}
	})

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

	if p.fionreadFixupEnabled {
		p.verifyFIONREADFix()
	}

	for _, it := range p.Iters() {
		if err := it.Run(p.log); err != nil {
			p.log.Error("error running iterator", "error", err)
		}
	}

	<-ctx.Done()

	p.bpfObjects.Close()
	p.bpfIterObjects.Close()
	p.bpfFionreadFixupObjects.Close()

	p.log.Debug("tpinjector terminated")
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return false
}
