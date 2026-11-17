// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/exceptions"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// Mirrors enum go_exception_pid_flags in bpf/gotracer/types/errors.h
const (
	goExceptionPIDEnabled         uint8 = 1 << 0
	goExceptionPIDPanics          uint8 = 1 << 1
	goExceptionPIDFormattedErrors uint8 = 1 << 2
)

const (
	goPanicSymbol   = "runtime.gopanic"
	goCleanupSymbol = "runtime.casgstatus"
	// Go 1.26+ splits fmt.Errorf into an inlinable wrapper and this helper
	goErrorfSymbol       = "fmt.errorf"
	goLegacyErrorfSymbol = "fmt.Errorf"
)

// GoExceptionProbeSymbols returns every symbol the exception probes can attach to.
func GoExceptionProbeSymbols() []string {
	return []string{goPanicSymbol, goErrorfSymbol, goLegacyErrorfSymbol, goCleanupSymbol}
}

func isGoExceptionSymbol(symbol string) bool {
	return slices.Contains(GoExceptionProbeSymbols(), symbol)
}

// goExceptionProbeGroups attaches the exception probes per process, so that
// processes of one executable follow their own service's settings. fmt.errorf
// comes before fmt.Errorf, which registerExceptionProbe then skips.
func (p *Tracer) goExceptionProbeGroups() []ebpfcommon.GoProbeGroup {
	if !p.exceptionsEnabled {
		return nil
	}

	probes := []ebpfcommon.GoProbe{
		{Symbol: goErrorfSymbol, Probe: &ebpfcommon.ProbeDesc{End: p.bpfObjects.ObiUprobeFmtErrorfRet}},
		{Symbol: goLegacyErrorfSymbol, Probe: &ebpfcommon.ProbeDesc{End: p.bpfObjects.ObiUprobeFmtErrorfRet}},
		{Symbol: goPanicSymbol, Probe: &ebpfcommon.ProbeDesc{Start: p.bpfObjects.ObiUprobeRuntimeGopanic}},
	}

	if !p.traceCtxMapEnabled {
		probes = append(probes, ebpfcommon.GoProbe{
			Symbol: goCleanupSymbol,
			Probe:  &ebpfcommon.ProbeDesc{Start: p.bpfObjects.ObiUprobeRuntimeCasgstatus},
		})
	}

	groups := make([]ebpfcommon.GoProbeGroup, 0, len(probes))
	for _, probe := range probes {
		probe.ProcessScoped = true
		groups = append(groups, ebpfcommon.GoProbeGroup{
			Name:   "go_exceptions " + probe.Symbol,
			Probes: []ebpfcommon.GoProbe{probe},
		})
	}
	return groups
}

// goExceptionProcess is a process that captures exceptions, and the probe
// links attached for it.
type goExceptionProcess struct {
	executable executableIdentity
	links      []io.Closer
	flags      uint8
}

func (p *Tracer) registerExceptionProbe(executable executableIdentity, probe ebpfcommon.GoProbe) {
	p.exceptionsMu.Lock()
	defer p.exceptionsMu.Unlock()

	registered := p.exceptionProbes[executable]
	// When fmt.errorf exists, fmt.Errorf only wraps it: probing both would
	// report an indirect fmt.Errorf call twice
	if probe.Symbol == goLegacyErrorfSymbol && slices.ContainsFunc(registered, func(r ebpfcommon.GoProbe) bool {
		return r.Symbol == goErrorfSymbol
	}) {
		return
	}
	p.exceptionProbes[executable] = append(registered, probe)

	for pid, process := range p.exceptionProcesses {
		if process.executable == executable && goExceptionProbeEnabled(process.flags, probe.Symbol) {
			process.links = append(process.links, p.attachExceptionProbeLocked(pid, executable, probe)...)
			p.exceptionProcesses[pid] = process
		}
	}
}

// unregisterExceptionProbes detaches the probes of a removed executable. Its
// processes stay tracked, so that a replacement registration attaches again.
func (p *Tracer) unregisterExceptionProbes(executable executableIdentity) {
	p.exceptionsMu.Lock()
	defer p.exceptionsMu.Unlock()

	delete(p.exceptionProbes, executable)
	for pid, process := range p.exceptionProcesses {
		if process.executable == executable {
			closeExceptionLinks(process.links)
			process.links = nil
			p.exceptionProcesses[pid] = process
		}
	}
}

// trackExceptionProcess attaches the exception probes of executable to pid.
func (p *Tracer) trackExceptionProcess(pid app.PID, executable executableIdentity, flags uint8) {
	p.exceptionsMu.Lock()
	defer p.exceptionsMu.Unlock()

	if process, ok := p.exceptionProcesses[pid]; ok {
		if process.executable == executable && process.flags == flags {
			return
		}
		closeExceptionLinks(process.links)
	}

	process := goExceptionProcess{executable: executable, flags: flags}
	for _, probe := range p.exceptionProbes[executable] {
		if !goExceptionProbeEnabled(flags, probe.Symbol) {
			continue
		}
		process.links = append(process.links, p.attachExceptionProbeLocked(pid, executable, probe)...)
	}
	p.exceptionProcesses[pid] = process
}

func (p *Tracer) untrackExceptionProcess(pid app.PID) {
	p.exceptionsMu.Lock()
	defer p.exceptionsMu.Unlock()

	if process, ok := p.exceptionProcesses[pid]; ok {
		closeExceptionLinks(process.links)
		delete(p.exceptionProcesses, pid)
	}
}

func (p *Tracer) closeExceptionResources() {
	p.exceptionsMu.Lock()
	defer p.exceptionsMu.Unlock()

	for pid, process := range p.exceptionProcesses {
		closeExceptionLinks(process.links)
		goSymbols.RemovePID(pid)
		goSymbols.RemoveExecutable(process.executable.Dev, process.executable.Ino)
	}
	for executable := range p.exceptionProbes {
		goSymbols.RemoveExecutable(executable.Dev, executable.Ino)
	}
	clear(p.exceptionProcesses)
	clear(p.exceptionProbes)
}

func (p *Tracer) attachExceptionProbeLocked(pid app.PID, executable executableIdentity, probe ebpfcommon.GoProbe) []io.Closer {
	links, err := p.attachGoExceptionProbe(pid, executable, probe.Probe)
	if err != nil {
		closeExceptionLinks(links)
		p.log.Warn("attaching Go exception probe", "pid", pid, "function", probe.Symbol, "error", err)
		return nil
	}
	return links
}

// attachGoExceptionProbe attaches probe to pid only: an entry probe at the
// function start, or a return probe at each of its RET instructions.
func attachGoExceptionProbe(pid app.PID, executable executableIdentity, probe *ebpfcommon.ProbeDesc) ([]io.Closer, error) {
	target, err := openTargetExecutable(pid, executable.Dev, executable.Ino)
	if err != nil {
		return nil, err
	}
	defer target.Close()

	targetPath := fmt.Sprintf("/proc/self/fd/%d", target.Fd())
	exe, err := link.OpenExecutable(targetPath)
	if err != nil {
		return nil, fmt.Errorf("opening target executable: %w", err)
	}

	program, addresses := probe.Start, []uint64{probe.StartOffset}
	if probe.End != nil {
		program, addresses = probe.End, probe.ReturnOffsets
	}
	closer, err := uprobe.Attach(exe, targetPath, program, uprobe.Options{Addresses: addresses, PID: uint32(pid)})
	if err != nil {
		return nil, err
	}
	return []io.Closer{closer}, nil
}

func closeExceptionLinks(links []io.Closer) {
	for _, l := range links {
		_ = l.Close()
	}
}

// privateExceptionEvents gives the Go tracer its own exception_events ring:
// the generic tracer reads the shared one, and it is not loaded when only Go
// processes are selected. The ring shrinks to a page when capture is off.
func (p *Tracer) privateExceptionEvents(spec *ebpf.CollectionSpec) {
	events := spec.Maps[BpfMapExceptionEvents]
	if events == nil {
		return
	}

	events.Pinning = ebpf.PinNone
	if !p.exceptionsEnabled {
		events.MaxEntries = uint32(os.Getpagesize())
	}
}

func (p *Tracer) readExceptionEvents(ctx context.Context, eventContext *ebpfcommon.EBPFEventContext) {
	if !p.exceptionsEnabled || eventContext.ExceptionInput == nil {
		return
	}

	go ebpfcommon.ForwardRingbufWithDrainContext(
		p.cfg,
		p.shutdownTimeout,
		p.bpfObjects.ExceptionEvents,
		func(_ context.Context, record *ringbuf.Record) (exceptions.Event, bool, error) {
			return ebpfcommon.ReadExceptionRecord(record, p.pidsFilter)
		},
		nil,
		p.log.With("ringbuf", "exception_events"),
		p.metrics,
	)(ctx, eventContext.ExceptionInput)
}

// RegisterExecutable keeps the symbols of an executable readable until
// UnregisterExecutable, for whichever of its processes captures exceptions.
// The symbol table is only loaded for the first exception.
func (p *Tracer) RegisterExecutable(fileInfo *exec.FileInfo) {
	if !p.exceptionsEnabled || fileInfo == nil {
		return
	}

	if err := goSymbols.AddExecutable(fileInfo); err != nil {
		p.log.Debug("Go exception stacks will not be symbolized", "pid", fileInfo.Pid(), "error", err)
	}
}

func (p *Tracer) UnregisterExecutable(dev, ino uint64) {
	if !p.exceptionsEnabled {
		return
	}

	goSymbols.RemoveExecutable(dev, ino)
}

func (p *Tracer) registerExceptionPID(pid app.PID, fileInfo *exec.FileInfo) {
	if !p.exceptionsEnabled || fileInfo == nil {
		return
	}

	settings := fileInfo.ServiceAttrs().Exceptions
	if !settings.Enabled {
		p.unregisterExceptionPID(pid)
		return
	}

	if loadBias, err := procs.FindExeLoadBias(pid); err != nil {
		goSymbols.RemovePID(pid)
		p.log.Debug("Go exception stacks will not be symbolized", "pid", pid, "error", err)
	} else {
		goSymbols.BindPID(pid, fileInfo.Dev(), fileInfo.Ino(), loadBias)
	}

	flags := goExceptionPIDEnabled
	if settings.Go.PanicsEnabled() {
		flags |= goExceptionPIDPanics
	}
	if settings.Go.FormattedErrors {
		flags |= goExceptionPIDFormattedErrors
	}
	if flags == goExceptionPIDEnabled {
		p.unregisterExceptionPID(pid)
		return
	}
	if err := p.bpfObjects.GoExceptionPids.Put(uint32(pid), flags); err != nil {
		p.log.Warn("enabling Go exception capture", "pid", pid, "error", err)
		p.unregisterExceptionPID(pid)
		return
	}
	p.trackExceptionProcess(pid, executableIdentity{Dev: fileInfo.Dev(), Ino: fileInfo.Ino()}, flags)
}

func (p *Tracer) unregisterExceptionPID(pid app.PID) {
	if !p.exceptionsEnabled {
		return
	}

	p.untrackExceptionProcess(pid)
	if err := p.bpfObjects.GoExceptionPids.Delete(uint32(pid)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		p.log.Debug("disabling Go exception capture", "pid", pid, "error", err)
	}
	goSymbols.RemovePID(pid)
}

func goExceptionProbeEnabled(flags uint8, symbol string) bool {
	switch symbol {
	case goCleanupSymbol:
		return flags&(goExceptionPIDPanics|goExceptionPIDFormattedErrors) != 0
	case goPanicSymbol:
		return flags&goExceptionPIDPanics != 0
	case goErrorfSymbol, goLegacyErrorfSymbol:
		return flags&goExceptionPIDFormattedErrors != 0
	default:
		return false
	}
}
