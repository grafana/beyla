// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	common "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func ptlog() *slog.Logger { return slog.With("component", "ebpf.ProcessTracer") }

type instrumenter struct {
	key                         ExecutableKey
	uprobeKey                   ExecutableKey
	offsets                     *goexec.Offsets
	exe                         *link.Executable
	closables                   []io.Closer
	optionalGoProbeGroupClosers []io.Closer
	processScopedGoProbes       []processScopedGoProbeRegistration
	modules                     map[uint64]struct{}
	metrics                     imetrics.Reporter
	processName                 string
}

type uprobeTargetResolver interface {
	ResolveUprobeTarget(*link.Executable, uint64) (uint64, uint64, error)
}

const goUprobeTargetProbeSymbol = "runtime.newproc1"

func loadSpec(eventContext *common.EBPFEventContext, bundle *common.SpecBundle, otelBPFFSPath string, idx int, cache *btf.Cache) error {
	if err := ebpfconvenience.LoadSpec(
		bundle.Spec,
		bundle.Objects,
		bundle.Constants,
		eventContext.EBPFMaps,
		&eventContext.MapsLock,
		otelBPFFSPath,
		cache,
	); err != nil {
		return fmt.Errorf("loading spec %d: %w", idx, err)
	}

	return nil
}

func closeLoadedSpecs(bundles []*common.SpecBundle) {
	for _, bundle := range bundles {
		if c, ok := bundle.Objects.(io.Closer); ok {
			c.Close()
		}
	}
}

func unloadInternalMaps(eventContext *common.EBPFEventContext) {
	eventContext.MapsLock.Lock()
	defer eventContext.MapsLock.Unlock()

	for _, v := range eventContext.EBPFMaps {
		v.Close()
	}

	eventContext.EBPFMaps = make(map[string]*ebpf.Map)
}

func NewProcessTracer(tracerType ProcessTracerType, programs []Tracer, cfg *obi.Config, metrics imetrics.Reporter) *ProcessTracer {
	return &ProcessTracer{
		log:                       ptlog().With("type", tracerType),
		Programs:                  programs,
		Type:                      tracerType,
		Instrumentables:           map[ExecutableKey]*instrumenter{},
		instrumentableGenerations: map[ExecutableKey]uint64{},
		shutdownTimeout:           cfg.ShutdownTimeout,
		metrics:                   metrics,
		bpffsPath:                 cfg.EBPF.BPFFSPath,
	}
}

type tracerInstance struct {
	implType string
	done     atomic.Bool
}

func unfinishedTracerTypes(tracers []tracerInstance) []string {
	unfinished := make([]string, 0, len(tracers))
	for i := range tracers {
		if !tracers[i].done.Load() {
			unfinished = append(unfinished, tracers[i].implType)
		}
	}
	return unfinished
}

func (pt *ProcessTracer) Run(
	ctx context.Context,
	ebpfEventContext *common.EBPFEventContext,
	out *msg.Queue[[]request.Span],
) {
	pt.log.Debug("starting process tracer")

	// Searches for traceable functions
	trcrs := pt.Programs
	wg := sync.WaitGroup{}
	runningTracers := make([]tracerInstance, 0, len(trcrs))
	for i := range trcrs {
		idx := i
		t := trcrs[idx]
		wg.Add(1)
		runningTracers = append(runningTracers, tracerInstance{
			implType: reflect.TypeOf(t).String(),
		})
		go func() {
			defer wg.Done()
			t.Run(ctx, ebpfEventContext, out)
			runningTracers[idx].done.Store(true)
		}()
	}

	<-ctx.Done()

	tracersEnded := make(chan struct{})
	go func() {
		wg.Wait()
		close(tracersEnded)
	}()
	unloadInternalMaps(ebpfEventContext)

	hasWarned := false
	for {
		select {
		// notifying before OBI times out on finish
		case <-time.After(3 * pt.shutdownTimeout / 4):
			pt.log.Warn("some process tracers did not finish", "tracers", unfinishedTracerTypes(runningTracers))
			hasWarned = true
		case <-tracersEnded:
			if hasWarned {
				pt.log.Info("all process tracers finished")
			}
			return
		}
	}
}

func (pt *ProcessTracer) makeOtelBPFFSPath() (string, error) {
	otelPath := path.Join(pt.bpffsPath, "otel")

	if err := os.MkdirAll(otelPath, 0o1700); err != nil {
		return "", fmt.Errorf("creating bpffs otel path: %w", err)
	}
	if err := unix.Faccessat(
		unix.AT_FDCWD,
		otelPath,
		unix.R_OK|unix.W_OK|unix.X_OK,
		unix.AT_EACCESS,
	); err != nil {
		return "", fmt.Errorf("accessing bpffs otel path: %w", err)
	}

	return otelPath, nil
}

func (pt *ProcessTracer) setupOtelBPFFSPath(bundles []*common.SpecBundle) string {
	// Set up BPF FS path once for all specs
	otelBPFFSPath, err := pt.makeOtelBPFFSPath()

	if err == nil {
		return otelBPFFSPath
	}

	log := ptlog()

	log.Warn("creating or accessing OTEL namespace in bpffs failed (is bpffs mounted and accessible?)",
		"bpffs_path", pt.bpffsPath, "err", err)

	log.Warn("OBI will use process-internal maps; external features depending on pinned maps (e.g., profile correlation) will be disabled")

	// disable pinning for ALL specs
	for _, bundle := range bundles {
		for _, v := range bundle.Spec.Maps {
			if v.Pinning == ebpf.PinByName {
				v.Pinning = ebpfconvenience.PinInternal
			}
		}
	}

	return ""
}

func setupBPFMapSizes(spec *ebpf.CollectionSpec, cfg *obi.Config) {
	ebpfconvenience.SetupMapSizes(spec, cfg.EBPF.MapsConfig.GlobalScaleFactor)
}

func (pt *ProcessTracer) loadAndAssign(eventContext *common.EBPFEventContext, p Tracer, cfg *obi.Config, cache *btf.Cache) error {
	p.SetEventContext(eventContext)

	bundles, err := p.LoadSpecs()
	if err != nil {
		return fmt.Errorf("loading eBPF program specs: %w", err)
	}

	otelBPFFSPath := pt.setupOtelBPFFSPath(bundles)

	for i, bundle := range bundles {
		// set max entries map using user defined values
		setupBPFMapSizes(bundle.Spec, cfg)

		if err := loadSpec(eventContext, bundle, otelBPFFSPath, i, cache); err != nil {
			closeLoadedSpecs(bundles[:i])
			return err
		}
	}

	return nil
}

func (pt *ProcessTracer) loadTracer(eventContext *common.EBPFEventContext, p Tracer, log *slog.Logger, cfg *obi.Config, cache *btf.Cache) error {
	plog := log.With("program", reflect.TypeOf(p))
	plog.Debug("loading eBPF program", "type", pt.Type)

	err := pt.loadAndAssign(eventContext, p, cfg, cache)

	if err != nil && (strings.Contains(err.Error(), "unknown func bpf_probe_write_user") ||
		strings.Contains(err.Error(), "cannot use helper bpf_probe_write_user")) {
		plog.Warn("Failed to enable Go write memory distributed tracing context-propagation " +
			"and/or log enricher on a Linux Kernel without write memory support. " +
			"To avoid seeing this message, please ensure you have correctly mounted /sys/kernel/security " +
			"and ensure OBI has the SYS_ADMIN linux capability. " +
			"For more details set OTEL_EBPF_LOG_LEVEL=DEBUG.")

		common.IntegrityModeOverride = true
		err = pt.loadAndAssign(eventContext, p, cfg, cache)
	}

	if err != nil {
		printVerifierErrorInfo(err)
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	// Setup any tail call jump tables
	p.SetupTailCalls()

	i := instrumenter{} // dummy instrumenter to setup the kprobes, socket filters and tracepoint probes

	// Kprobes to be used for native instrumentation points
	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Tracepoints support
	if err := i.tracepoints(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sock filters support
	if err := i.sockfilters(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sock_msg support
	if err := i.sockmsgs(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sockops support
	if err := i.sockops(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.iters(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.tracing(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	return nil
}

func (pt *ProcessTracer) loadTracers(eventContext *common.EBPFEventContext, cfg *obi.Config) error {
	eventContext.LoadLock.Lock()
	defer eventContext.LoadLock.Unlock()

	log := ptlog()

	loadedPrograms := make([]Tracer, 0, len(pt.Programs))

	cache := btf.NewCache()

	for _, p := range pt.Programs {
		if err := pt.loadTracer(eventContext, p, log, cfg, cache); err != nil {
			log.Warn("couldn't load tracer", "error", err, "required", p.Required())
			if p.Required() {
				return err
			}
		} else {
			loadedPrograms = append(loadedPrograms, p)
			eventContext.Capabilities |= p.Capabilities()
		}
	}

	pt.Programs = loadedPrograms

	return nil
}

func (pt *ProcessTracer) Init(eventContext *common.EBPFEventContext, cfg *obi.Config) error {
	return pt.loadTracers(eventContext, cfg)
}

func (pt *ProcessTracer) NewExecutableInstance(ie *Instrumentable) error {
	key := ExecutableKey{Dev: ie.FileInfo.Dev(), Ino: ie.FileInfo.Ino()}
	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()

	if i, ok := pt.Instrumentables[key]; ok {
		maps, err := processMaps(ie.FileInfo.Pid())
		if err != nil {
			return err
		}
		for _, p := range pt.Programs {
			p.ProcessBinary(ie.FileInfo)
			// Uprobes to be used for native module instrumentation points
			if err := i.uprobes(ie.FileInfo.Pid(), p, maps); err != nil {
				printVerifierErrorInfo(err)
				return err
			}
			if err := i.usdtProbes(ie.FileInfo.Pid(), ie.FileInfo.Ns(), p, maps); err != nil {
				printVerifierErrorInfo(err)
				return err
			}
		}
	} else {
		pt.log.Warn("Attempted to update non-existent tracer", "path", ie.FileInfo.CmdExePath(), "pid", ie.FileInfo.Pid())
	}

	return nil
}

func (pt *ProcessTracer) NewExecutable(exe *link.Executable, ie *Instrumentable) error {
	i := instrumenter{
		key:         ExecutableKey{Dev: ie.FileInfo.Dev(), Ino: ie.FileInfo.Ino()},
		exe:         exe,
		offsets:     ie.Offsets, // this is needed for the function offsets, not fields
		modules:     map[uint64]struct{}{},
		metrics:     pt.metrics,
		processName: ie.FileInfo.ExecutableName(),
	}
	committed := false
	defer func() {
		if !committed {
			i.rollbackOptionalGoProbeGroups()
		}
	}()

	maps, err := processMaps(ie.FileInfo.Pid())
	if err != nil {
		return err
	}

	for _, p := range pt.Programs {
		p.RegisterOffsets(ie.FileInfo, ie.Offsets)
	}

	if uprobeKey, ok := pt.resolveUprobeTarget(exe, ie.Offsets); ok {
		i.uprobeKey = uprobeKey
		if existing := pt.instrumenterForUprobeTarget(uprobeKey); existing != nil {
			for _, p := range pt.Programs {
				if err := existing.uprobes(ie.FileInfo.Pid(), p, maps); err != nil {
					printVerifierErrorInfo(err)
					return err
				}

				if err := existing.usdtProbes(ie.FileInfo.Pid(), ie.FileInfo.Ns(), p, maps); err != nil {
					printVerifierErrorInfo(err)
					return err
				}
			}

			pt.commitInstrumenterForKey(i.key, existing, ie)
			committed = true
			return nil
		}
	}

	for _, p := range pt.Programs {
		// Go style Uprobes
		if err := i.goprobes(p); err != nil {
			printVerifierErrorInfo(err)
			return err
		}

		// Uprobes to be used for native module instrumentation points
		if err := i.uprobes(ie.FileInfo.Pid(), p, maps); err != nil {
			printVerifierErrorInfo(err)
			return err
		}

		if err := i.usdtProbes(ie.FileInfo.Pid(), ie.FileInfo.Ns(), p, maps); err != nil {
			printVerifierErrorInfo(err)
			return err
		}
	}

	pt.commitInstrumenter(&i, ie)
	committed = true

	return nil
}

func (pt *ProcessTracer) resolveUprobeTarget(exe *link.Executable, offsets *goexec.Offsets) (ExecutableKey, bool) {
	if pt.Type != Go || offsets == nil {
		return ExecutableKey{}, false
	}

	probes, ok := offsets.Funcs[goUprobeTargetProbeSymbol]
	if !ok || len(probes) == 0 {
		return ExecutableKey{}, false
	}

	for _, p := range pt.Programs {
		resolver, ok := p.(uprobeTargetResolver)
		if !ok {
			continue
		}

		dev, ino, err := resolver.ResolveUprobeTarget(exe, probes[0].Start)
		if err != nil {
			ptlog().Debug("resolving kernel uprobe target failed", "error", err)
			return ExecutableKey{}, false
		}

		return ExecutableKey{Dev: dev, Ino: ino}, true
	}

	return ExecutableKey{}, false
}

func (pt *ProcessTracer) instrumenterForUprobeTarget(key ExecutableKey) *instrumenter {
	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()

	for _, i := range pt.Instrumentables {
		if i.uprobeKey == key {
			return i
		}
	}

	return nil
}

func (pt *ProcessTracer) commitInstrumenter(i *instrumenter, ie *Instrumentable) {
	pt.commitInstrumenterForKey(i.key, i, ie)
}

func (pt *ProcessTracer) commitInstrumenterForKey(key ExecutableKey, i *instrumenter, ie *Instrumentable) {
	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()

	if previous := pt.Instrumentables[key]; previous != nil && previous != i {
		pt.removeInstrumenter(key, previous)
	}
	if pt.Instrumentables == nil {
		pt.Instrumentables = map[ExecutableKey]*instrumenter{}
	}
	pt.Instrumentables[key] = i
	ie.ExecutableGeneration = pt.recordExecutableGeneration(key)
	i.registerProcessScopedGoProbes(key)
}

func (pt *ProcessTracer) recordExecutableGeneration(key ExecutableKey) uint64 {
	pt.nextExecutableGeneration++
	if pt.nextExecutableGeneration == 0 {
		pt.nextExecutableGeneration++
	}
	if pt.instrumentableGenerations == nil {
		pt.instrumentableGenerations = map[ExecutableKey]uint64{}
	}
	pt.instrumentableGenerations[key] = pt.nextExecutableGeneration

	return pt.nextExecutableGeneration
}

func (pt *ProcessTracer) UnlinkExecutable(info *exec.FileInfo, generation uint64) {
	key := ExecutableKey{Dev: info.Dev(), Ino: info.Ino()}
	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()

	i, ok := pt.Instrumentables[key]
	if !ok {
		pt.log.Warn("Unable to find executable to unlink",
			"path", info.CmdExePath(),
			"pid", info.Pid(),
			"inode", info.Ino())
		return
	}
	currentGeneration := pt.instrumentableGenerations[key]
	if currentGeneration != generation {
		pt.log.Debug("Ignoring stale executable unlink",
			"path", info.CmdExePath(),
			"pid", info.Pid(),
			"inode", info.Ino(),
			"generation", generation,
			"current_generation", currentGeneration)
		return
	}

	pt.removeInstrumenter(key, i)
}

func (pt *ProcessTracer) removeInstrumenter(key ExecutableKey, i *instrumenter) {
	for _, p := range pt.Programs {
		if processScopedTracer, ok := p.(processScopedGoProbeTracer); ok {
			processScopedTracer.UnregisterProcessScopedGoProbes(key.Dev, key.Ino)
		}
	}
	delete(pt.Instrumentables, key)
	delete(pt.instrumentableGenerations, key)
	for _, remaining := range pt.Instrumentables {
		if remaining == i {
			return
		}
	}
	pt.unlinkInstrumenter(i)
}

func (pt *ProcessTracer) unlinkInstrumenter(i *instrumenter) {
	for _, c := range i.closables {
		if err := c.Close(); err != nil {
			pt.log.Debug("Unable to close on unlink", "closable", c)
		}
	}
	for ino := range i.modules {
		for _, p := range pt.Programs {
			p.UnlinkInstrumentedLib(ino)
		}
	}
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

func RunUtilityTracer(ctx context.Context, eventContext *common.EBPFEventContext, p UtilityTracer, cfg *obi.Config) error {
	i := instrumenter{}
	plog := ptlog()
	plog.Debug("loading independent eBPF program")

	bundles, err := p.LoadSpecs()
	if err != nil {
		return fmt.Errorf("loading eBPF program specs: %w", err)
	}

	for idx, bundle := range bundles {
		// Utility tracers don't pin maps (empty pin path), so no pinned
		// map conflicts are possible — the empty path is intentional.
		setupBPFMapSizes(bundle.Spec, cfg)
		if err := loadSpec(eventContext, bundle, "", idx, nil); err != nil {
			closeLoadedSpecs(bundles[:idx])
			printVerifierErrorInfo(err)
			return err
		}
	}

	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.tracepoints(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	go p.Run(ctx)

	return nil
}
