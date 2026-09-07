// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"debug/elf"
	"errors"
	"fmt"
	"strings"
)

// findPrivateCollectorProbe resolves a return probe for a visible private collector symbol.
// Some full Docker Official Images omit SystemTap notes but retain LTO-suffixed collector symbols.
func findPrivateCollectorProbe(file *elf.File) (GCCompletionProbe, error) {
	if file == nil || file.Machine != elf.EM_X86_64 {
		return GCCompletionProbe{}, fmt.Errorf("%w: invalid CPython ELF", errUnsupportedLayout)
	}
	target, err := privateCollectorSymbolAddress(file)
	if err != nil {
		return GCCompletionProbe{}, err
	}
	fileOffset, err := strictELFFileOffset(file, target, true)
	if err != nil {
		return GCCompletionProbe{}, err
	}
	return GCCompletionProbe{Kind: GCCompletionProbePrivateReturn, FileOffset: fileOffset}, nil
}

func privateCollectorSymbolAddress(file *elf.File) (uint64, error) {
	var tables [][]elf.Symbol
	for _, read := range []func() ([]elf.Symbol, error){file.Symbols, file.DynamicSymbols} {
		symbols, err := read()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return 0, err
		}
		tables = append(tables, symbols)
	}
	return selectPrivateCollectorSymbol(tables...)
}

// selectPrivateCollectorSymbol accepts one recognized address across both symbol tables and rejects ambiguity.
func selectPrivateCollectorSymbol(tables ...[]elf.Symbol) (uint64, error) {
	var target uint64
	for _, symbols := range tables {
		for _, symbol := range symbols {
			// Require a defined collector function with a concrete body. Compiler-generated
			// .cold fragments do not represent the normal collector completion path.
			if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || symbol.Section == elf.SHN_UNDEF ||
				symbol.Value == 0 || strings.Contains(symbol.Name, ".cold") ||
				!recognizedCollectorName(symbol.Name) {
				continue
			}
			if target != 0 && target != symbol.Value {
				return 0, fmt.Errorf("%w: ambiguous private CPython collector symbols", errUnsupportedLayout)
			}
			target = symbol.Value
		}
	}
	if target == 0 {
		return 0, fmt.Errorf("%w: no private CPython collector symbol", errUnsupportedLayout)
	}
	return target, nil
}

func recognizedCollectorName(name string) bool {
	for _, base := range []string{"collect_with_callback", "gc_collect_main", "_PyGC_Collect", "gc_collect_internal"} {
		if name == base || strings.HasPrefix(name, base+".") {
			return true
		}
	}
	return false
}

// strictELFFileOffset maps one virtual address to exactly one file-backed load segment.
func strictELFFileOffset(file *elf.File, address uint64, executable bool) (uint64, error) {
	var offset uint64
	matches := 0
	for _, program := range file.Progs {
		// Require a file-backed load segment. Probe locations must also belong to
		// an executable segment, while semaphore locations can belong to data.
		if program.Type != elf.PT_LOAD || executable && program.Flags&elf.PF_X == 0 ||
			address < program.Vaddr || address-program.Vaddr >= program.Filesz {
			continue
		}
		candidate := program.Off + address - program.Vaddr
		if candidate < program.Off || candidate == 0 {
			return 0, fmt.Errorf("%w: invalid CPython probe file offset", errUnsupportedLayout)
		}
		offset = candidate
		matches++
	}
	if matches != 1 {
		return 0, fmt.Errorf("%w: CPython probe address maps to %d file segments", errUnsupportedLayout, matches)
	}
	return offset, nil
}
