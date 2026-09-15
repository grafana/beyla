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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/hashicorp/golang-lru/v2/expirable"
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
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -tags privileged_tests -target amd64,arm64 BpfH2MutationProbe ../../../../bpf/tests/testdata/h2_mutation_peer.c -- -I../../../../bpf -I../../../../bpf

type Tracer struct {
	cfg                     *obi.Config
	bpfObjects              BpfObjects
	bpfIterObjects          BpfIterObjects
	bpfFionreadFixupObjects BpfFionreadFixupObjects
	closers                 []io.Closer
	log                     *slog.Logger
	iters                   []*ebpfcommon.Iter
	fionreadOnce            sync.Once
	fionreadProbe           func(cookies *ebpf.Map) (bool, error)
	fionreadBroken          bool
	fionreadFixupEnabled    bool
	sockhashOnce            sync.Once
	sockhashOK              bool
	iterMu                  sync.Mutex
	itersOnce               sync.Once
	seenNetns               *expirable.LRU[uint64, struct{}]
	netnsAttempts           *expirable.LRU[uint64, int]
	backfillDisabled        bool
}

const (
	seenNetnsCacheLen = 1024
	// the kernel reuses netns inodes and a capacity bound never evicts below the cap, so a new
	// container landing on a freed inode would look already backfilled
	seenNetnsTTL = 5 * time.Minute
	// a namespace that keeps failing is dropped, so one broken container cannot stop the
	// backfill for every other namespace on the host
	maxNetnsAttempts = 3
)

func New(cfg *obi.Config) *Tracer {
	log := slog.With("component", "tpinjector")
	return &Tracer{
		log:           log,
		cfg:           cfg,
		fionreadProbe: sockhashFIONREADProbe,
		seenNetns:     expirable.NewLRU[uint64, struct{}](seenNetnsCacheLen, nil, seenNetnsTTL),
		netnsAttempts: expirable.NewLRU[uint64, int](seenNetnsCacheLen, nil, seenNetnsTTL),
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
	if err := verifyH2MutationSupport(); err != nil {
		p.log.Warn("HTTP/2 socket mutation disabled because the rollback helper is unavailable",
			"error", err)
		disableH2SocketMutation(spec)
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
			p.log.Warn("cannot load the FIONREAD compensation (kernel lockdown?)", "error", err)
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

func verifyH2MutationSupport() error {
	if err := features.HaveProgramHelper(ebpf.SkMsg, asm.FnMsgPopData); err != nil {
		return fmt.Errorf("sk_msg helper %s: %w", asm.FnMsgPopData, err)
	}
	return nil
}

func disableH2SocketMutation(spec *ebpf.CollectionSpec) {
	fallback, ok := spec.Programs["obi_packet_extender_write_h2_tp_no_rollback"]
	if !ok {
		return
	}

	fallback.Name = "obi_packet_extender_write_h2_tp"
	spec.Programs["obi_packet_extender_write_h2_tp"] = fallback
	spec.Programs["obi_packet_extender_write_h2_tp_no_rollback"] = &ebpf.ProgramSpec{
		Name: "obi_packet_extender_write_h2_tp_no_rollback",
		Type: ebpf.SkMsg,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
		License: "Dual MIT/GPL",
	}
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
	if !p.sockhashSafe() {
		return nil
	}

	return []ebpfcommon.SockMsg{
		{
			Program:  p.bpfObjects.ObiPacketExtender,
			MapFD:    p.bpfObjects.SockDir.FD(),
			AttachAs: ebpf.AttachSkMsgVerdict,
		},
	}
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	if !p.sockhashSafe() {
		return nil
	}

	return []ebpfcommon.SockOps{
		{
			Program:  p.bpfObjects.ObiSockmapTracker,
			AttachAs: ebpf.AttachCGroupSockOps,
		},
	}
}

// Iters is called from both AllowPID (discovery) and Run (pipeline) goroutines
func (p *Tracer) Iters() []*ebpfcommon.Iter {
	if !p.sockhashSafe() {
		return nil
	}

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
