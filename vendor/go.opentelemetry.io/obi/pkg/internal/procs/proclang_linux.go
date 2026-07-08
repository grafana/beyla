// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"debug/elf"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/fastelf"
)

func FindProcLanguage(pid app.PID) svc.InstrumentableType {
	maps, err := FindLibMaps(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	// We first check for the languages as cheaply as possible when
	// know they link certain libraries that can tell us the language.
	for _, m := range maps {
		t := instrumentableFromModuleMapSharedLib(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	// We must find the language type from the binary first
	// before resorting to discovery by path or environment variables.
	// For example, a Go application can be called 'node' and we must
	// not identify this application as Node.js.
	filePath, err := resolveProcBinary(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	t := findLanguageFromElf(filePath)

	if t != svc.InstrumentableGeneric {
		return t
	}

	for _, m := range maps {
		t := instrumentableFromModuleMap(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	t = instrumentableFromPath(filePath)
	if t != svc.InstrumentableGeneric {
		return t
	}

	// Last resort to tell Generic from C++ (and maybe others in the future)
	for _, m := range maps {
		t := instrumentableLastResort(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	return svc.InstrumentableGeneric
}

func resolveProcBinary(pid app.PID) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	realPath, err := os.Readlink(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to read process binary: %w", err)
	}

	return fmt.Sprintf("/proc/%d/root%s", pid, realPath), nil
}

func findLanguageFromElf(filePath string) (result svc.InstrumentableType) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("panic while parsing ELF file", "file", filePath, "panic", r)
			result = svc.InstrumentableGeneric
		}
	}()

	ctx, err := fastelf.NewElfContextFromFile(filePath)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	defer ctx.Close()

	if ctx.HasSection(".gopclntab") {
		return svc.InstrumentableGolang
	}

	return matchExeSymbols(ctx)
}

func contains(slice []string, value string) bool {
	return slices.Contains(slice, value)
}

type symbolCollector struct {
	addresses   map[string]Sym
	symbolNames []string
	matches     func(string, []string) (string, bool)
}

func collectSymbols(f *elf.File, syms []elf.Symbol, collectors []symbolCollector, types ...elf.SymType) {
	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}
	for _, s := range syms {
		if !slices.Contains(types, elf.ST_TYPE(s.Info)) {
			continue
		}

		var sym *Sym
		for _, collector := range collectors {
			key, ok := collector.matches(s.Name, collector.symbolNames)
			if !ok {
				continue
			}

			if sym == nil {
				resolvedSym := resolveSymbol(f, s)
				sym = &resolvedSym
			}
			collector.addresses[key] = *sym
		}
	}
}

func FindExeSymbols(f *elf.File, symbolNames []string, types ...elf.SymType) (map[string]Sym, error) {
	exactSyms, _, err := FindExeSymbolsByNameAndSubstring(f, symbolNames, nil, types...)
	return exactSyms, err
}

func FindExeSymbolsBySubstring(f *elf.File, symbolSubstrings []string, types ...elf.SymType) (map[string]Sym, error) {
	_, substringSyms, err := FindExeSymbolsByNameAndSubstring(f, nil, symbolSubstrings, types...)
	return substringSyms, err
}

func FindExeSymbolsByNameAndSubstring(f *elf.File, symbolNames, symbolSubstrings []string, types ...elf.SymType) (map[string]Sym, map[string]Sym, error) {
	exactAddresses := map[string]Sym{}
	substringAddresses := map[string]Sym{}
	collectors := []symbolCollector{
		{
			addresses:   exactAddresses,
			symbolNames: symbolNames,
			matches:     exactSymbolMatch,
		},
		{
			addresses:   substringAddresses,
			symbolNames: symbolSubstrings,
			matches:     substringSymbolMatch,
		},
	}

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, nil, err
	}

	collectSymbols(f, syms, collectors, types...)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, nil, err
	}

	collectSymbols(f, dynsyms, collectors, types...)

	return exactAddresses, substringAddresses, nil
}

func resolveSymbol(f *elf.File, s elf.Symbol) Sym {
	address := s.Value
	var p *elf.Prog

	// Loop over ELF segments.
	for _, prog := range f.Progs {
		// Skip uninteresting segments.
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
			address = s.Value - prog.Vaddr + prog.Off
			p = prog
			break
		}
	}

	return Sym{Name: s.Name, Off: address, Len: s.Size, Prog: p}
}

func exactSymbolMatch(symbolName string, names []string) (string, bool) {
	if contains(names, symbolName) {
		return symbolName, true
	}
	return "", false
}

func substringSymbolMatch(symbolName string, substrings []string) (string, bool) {
	for _, substring := range substrings {
		if strings.Contains(symbolName, substring) {
			return substring, true
		}
	}
	return "", false
}

func matchExeSymbols(ctx *fastelf.ElfContext) svc.InstrumentableType {
	for _, sec := range ctx.Sections {
		if sec == nil {
			continue
		}

		if sec.Type != fastelf.SHT_SYMTAB && sec.Type != fastelf.SHT_DYNSYM {
			continue
		}

		if int(sec.Link) >= len(ctx.Sections) {
			continue
		}

		strtab := ctx.Sections[sec.Link]

		strs, ok := ctx.SectionData(strtab)
		if !ok {
			continue
		}

		symOffset, symEntrySize, symCount, ok := ctx.SymbolTableBounds(sec)
		if !ok {
			continue
		}

		for i := range symCount {
			sym := fastelf.ReadStruct[fastelf.Elf64_Sym](ctx.Data, symOffset+i*symEntrySize)

			if sym == nil ||
				fastelf.SymType(sym.Info) != fastelf.STT_FUNC ||
				sym.Size == 0 ||
				sym.Value == 0 {
				continue
			}

			name := fastelf.GetCStringUnsafe(strs, sym.Name)

			t := instrumentableFromSymbolName(name)

			if t != svc.InstrumentableGeneric {
				return t
			}
		}
	}

	return svc.InstrumentableGeneric
}
