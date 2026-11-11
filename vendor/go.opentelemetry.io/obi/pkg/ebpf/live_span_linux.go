// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

// liveSpanProgram is implemented by language tracers. Keeping this interface in
// ebpf avoids making the shared instrumenter depend on a concrete tracer.
type liveSpanProgram interface {
	LiveSpanDescriptors(*config.CustomSpanSpec, uint64) []*ebpfcommon.USDTProbeDesc
	RegisterLiveSpan(*config.CustomSpanSpec, uint64, string, uint64)
	RemoveFailedLiveSpan(uint64)
	LiveSpanInvocationMap() *ebpf.Map
}

type liveSpanLinks struct {
	once        sync.Once
	closeErr    error
	links       []io.Closer
	cleanup     func()
	invocations *ebpf.Map
	cookie      uint64
}

func (l *liveSpanLinks) Invocations() (uint64, error) {
	var count uint64
	err := l.invocations.Lookup(l.cookie, &count)
	return count, err
}

func (l *liveSpanLinks) Close() error {
	l.once.Do(func() {
		for _, v := range slices.Backward(l.links) {
			l.closeErr = errors.Join(l.closeErr, v.Close())
		}
		if l.cleanup != nil {
			l.cleanup()
			l.cleanup = nil
		}
		l.links = nil
		if l.invocations != nil {
			if err := l.invocations.Delete(l.cookie); !errors.Is(err, ebpf.ErrKeyNotExist) {
				l.closeErr = errors.Join(l.closeErr, err)
			}
		}
	})
	return l.closeErr
}

// AttachLiveSpan reuses the loaded custom_span BPF program, spec map, ring
// buffer, and exporter. Its returned links belong only to this definition;
// they are never added to the executable-wide closer list.
func (pt *ProcessTracer) AttachLiveSpan(pid app.PID, ns uint32, span *config.CustomSpanSpec, cookie uint64, id string, generation uint64) (io.Closer, error) {
	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()
	if pt.stopped {
		return nil, errTracerStopped
	}
	if !ebpfcommon.HasAttachCookie() {
		return nil, errors.New("live probes require uprobe attach-cookie support")
	}
	var runtime liveSpanProgram
	for _, p := range pt.Programs {
		if r, ok := p.(liveSpanProgram); ok {
			runtime = r
			break
		}
	}
	if runtime == nil {
		return nil, errors.New("live custom_span tracer is not loaded for this process")
	}
	if span == nil {
		return nil, errors.New("live probe must target a function")
	}

	exePath, exeIno, err := resolveExePath(pid)
	if err != nil {
		return nil, fmt.Errorf("target PID %d is unavailable: %w", pid, err)
	}
	elfFile, err := elf.Open(exePath)
	if err != nil {
		return nil, fmt.Errorf("open target ELF: %w", err)
	}
	defer elfFile.Close()
	if _, offset := parsePreResolvedOffset(span.FunctionSymbol()); offset {
		if err := validateLiveOffset(elfFile, span.FunctionSymbol()); err != nil {
			return nil, err
		}
	}
	maps, err := processMaps(pid)
	if err != nil {
		return nil, fmt.Errorf("read target mappings: %w", err)
	}
	mappedPath := exeMappedPath(maps, exePath, exeIno)
	if mappedPath == "" {
		return nil, fmt.Errorf("target PID %d has no executable mapping", pid)
	}
	exe, err := link.OpenExecutable(exePath)
	if err != nil {
		return nil, fmt.Errorf("open target for uprobe: %w", err)
	}

	invocations := runtime.LiveSpanInvocationMap()
	if err := invocations.Update(cookie, uint64(0), ebpf.UpdateNoExist); err != nil {
		return nil, fmt.Errorf("initialize dynamic probe counter: %w", err)
	}
	attached := false
	defer func() {
		if !attached {
			_ = invocations.Delete(cookie)
		}
	}()

	probes := runtime.LiveSpanDescriptors(span, cookie)
	for _, probe := range probes {
		probe.Dynamic = true
		probe.Required = true
	}
	if !span.IsAnyFunction() {
		runtime.RegisterLiveSpan(span, cookie, id, generation)
		closers, err := (&instrumenter{}).usdtProbesAutoDiscover(pid, ns, maps, probes)
		if err != nil || len(closers) == 0 {
			runtime.RemoveFailedLiveSpan(cookie)
			if err == nil {
				err = errors.New("no USDT probes attached")
			}
			return nil, err
		}
		attached = true
		return &liveSpanLinks{links: closers, invocations: invocations, cookie: cookie, cleanup: func() { runtime.RemoveFailedLiveSpan(cookie) }}, nil
	}
	probe := probes[0]
	if _, offset := parsePreResolvedOffset(span.FunctionSymbol()); !offset {
		symbols, err := pt.symbols.symbols(exePath, elfFile)
		if err != nil {
			return nil, err
		}
		location, ok := symbols[span.FunctionSymbol()]
		if !ok {
			return nil, fmt.Errorf("function %q not found", span.FunctionSymbol())
		}
		probe.FunctionAddress, probe.FunctionSize = location.address, location.size
	}

	runtime.RegisterLiveSpan(span, cookie, id, generation)
	closers, err := (&instrumenter{}).instrumentUSDTProbe(exe, exePath, elfFile, pid, ns, maps, mappedPath, probe)
	if err != nil {
		runtime.RemoveFailedLiveSpan(cookie)
		return nil, err
	}
	if len(closers) == 0 {
		runtime.RemoveFailedLiveSpan(cookie)
		return nil, errors.New("resolved live probe produced no uprobe link")
	}
	attached = true
	return &liveSpanLinks{links: closers, invocations: invocations, cookie: cookie, cleanup: func() { runtime.RemoveFailedLiveSpan(cookie) }}, nil
}

func validateLiveOffset(elfFile *elf.File, target string) error {
	offset, ok := parsePreResolvedOffset(target)
	if !ok {
		return fmt.Errorf("invalid resolved offset %q", target)
	}
	for _, segment := range elfFile.Progs {
		if segment.Type == elf.PT_LOAD && segment.Flags&elf.PF_X != 0 &&
			offset >= segment.Off && offset-segment.Off < segment.Filesz {
			return nil
		}
	}
	return fmt.Errorf("offset %#x is outside executable PT_LOAD file ranges", offset)
}
