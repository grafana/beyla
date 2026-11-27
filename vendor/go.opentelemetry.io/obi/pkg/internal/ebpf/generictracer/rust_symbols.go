// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	"errors"
	"runtime"
	"slices"
	"strings"

	"github.com/ianlancetaylor/demangle"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type rustProbeKind uint8

const (
	rustTaskNew rustProbeKind = iota
	rustTaskRawNew
	rustTaskBind
	rustTaskPoll
	rustTaskDealloc
	rustTaskSpawn
	rustTaskSpawnPublic
	rustTaskSchedule
	rustTaskScheduleLocal
	rustTaskPublish
	rustTaskHarnessPoll
	rustTaskHarnessDealloc
	rustProbeCount
)

type rustProbeSymbols struct {
	addresses [rustProbeCount][]uint64
	hasHyper  bool
	hasTokio  bool
}

func resolveRustProbes(f *elf.File) (rustProbeSymbols, error) {
	var probes rustProbeSymbols
	matches := map[string]rustProbeKind{}
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB ||
		(f.Machine != elf.EM_X86_64 || runtime.GOARCH != "amd64") &&
			(f.Machine != elf.EM_AARCH64 || runtime.GOARCH != "arm64") {
		return probes, errors.New("rust uprobes require a native 64-bit amd64 or arm64 executable")
	}

	hasHyper := false
	hasTokio := false

	syms, err := procs.FindExeSymbolsMatching(f, func(name string) bool {
		if !strings.HasPrefix(name, "_R") && !strings.HasPrefix(name, "_ZN") {
			return false
		}

		if !strings.Contains(name, "tokio") && !strings.Contains(name, "hyper") {
			return false
		}

		decoded, err := demangle.ToString(name, demangle.NoClones, demangle.MaxLength(16))
		if err != nil {
			return false
		}

		if strings.Contains(decoded, "hyper::client::") {
			hasHyper = true
		}

		if strings.Contains(decoded, "tokio::runtime::") {
			hasTokio = true
		}

		kind, ok := rustSymbolKind(decoded)
		if !ok {
			return false
		}

		// The callback's names alias an ELF mapping that closes after the scan.
		matches[strings.Clone(name)] = kind
		return true
	})
	if err != nil {
		return probes, err
	}

	probes.hasHyper = hasHyper
	probes.hasTokio = hasTokio

	for name, sym := range syms {
		kind := matches[name]
		probes.addresses[kind] = append(probes.addresses[kind], sym.Off)
	}

	for kind := range probes.addresses {
		slices.Sort(probes.addresses[kind])
		probes.addresses[kind] = slices.Compact(probes.addresses[kind])
	}

	if len(syms) == 0 {
		return rustProbeSymbols{}, errors.New("no supported Tokio task symbols found")
	}

	return probes, nil
}

func rustSymbolKind(name string) (rustProbeKind, bool) {
	if name == "<tokio::runtime::scheduler::multi_thread::handle::Handle>::schedule_option_task_without_yield" {
		return rustTaskPublish, true
	}

	if strings.HasPrefix(name, "tokio::task::spawn::spawn::<") && strings.HasSuffix(name, ">") {
		return rustTaskSpawnPublic, true
	}

	if strings.HasPrefix(name, "<tokio::runtime::task::raw::RawTask>::new::<") && strings.HasSuffix(name, ">") {
		return rustTaskRawNew, true
	}

	if strings.HasPrefix(name, "<tokio::runtime::task::harness::Harness<") {
		if strings.HasSuffix(name, ">::poll") {
			return rustTaskHarnessPoll, true
		}

		if strings.HasSuffix(name, ">::dealloc") {
			return rustTaskHarnessDealloc, true
		}
	}

	// Tokio 0.2 can inline the thread-pool spawner into Runtime::spawn for individual futures.
	if (strings.HasPrefix(name, "<tokio::runtime::Runtime>::spawn::<") ||
		strings.HasPrefix(name, "<tokio::runtime::scheduler::Handle>::spawn::<") ||
		strings.HasPrefix(name, "<tokio::runtime::scheduler::multi_thread::handle::Handle>::spawn::<") ||
		strings.HasPrefix(name, "<tokio::runtime::scheduler::current_thread::Handle>::spawn::<") ||
		strings.HasPrefix(name, "<tokio::runtime::thread_pool::Spawner>::spawn::<") ||
		strings.HasPrefix(name, "<tokio::runtime::basic_scheduler::Spawner>::spawn::<")) && strings.HasSuffix(name, ">") {
		return rustTaskSpawn, true
	}

	if name == "<tokio::runtime::thread_pool::worker::Shared>::schedule" ||
		name == "<alloc::sync::Arc<tokio::runtime::scheduler::multi_thread::handle::Handle> as tokio::runtime::task::Schedule>::schedule" ||
		name == "<alloc::sync::Arc<tokio::runtime::scheduler::current_thread::Handle> as tokio::runtime::task::Schedule>::schedule" ||
		name == "<alloc::sync::Arc<tokio::runtime::basic_scheduler::Shared> as tokio::runtime::task::Schedule>::schedule" {
		return rustTaskSchedule, true
	}

	if name == "<tokio::runtime::scheduler::multi_thread::handle::Handle>::schedule_local" {
		return rustTaskScheduleLocal, true
	}

	if strings.HasPrefix(name, "<tokio::runtime::task::list::OwnedTasks<") && strings.HasSuffix(name, ">::bind_inner") {
		return rustTaskBind, true
	}

	if strings.HasPrefix(name, "tokio::runtime::task::raw::poll::<") || name == "tokio::runtime::task::raw::poll" {
		return rustTaskPoll, true
	}

	if strings.HasPrefix(name, "tokio::runtime::task::raw::dealloc::<") || name == "tokio::runtime::task::raw::dealloc" {
		return rustTaskDealloc, true
	}

	if strings.HasPrefix(name, "<tokio::runtime::task::core::Cell<") && strings.HasSuffix(name, ">::new") {
		return rustTaskNew, true
	}

	return 0, false
}
