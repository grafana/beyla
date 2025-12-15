// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"slices"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/fastelf"
)

func FindProcLanguage(pid int32) svc.InstrumentableType {
	maps, err := FindLibMaps(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	for _, m := range maps {
		t := instrumentableFromModuleMap(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	filePath, err := resolveProcBinary(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	t := findLanguageFromElf(filePath)

	if t != svc.InstrumentableGeneric {
		return t
	}

	t = instrumentableFromPath(filePath)
	if t != svc.InstrumentableGeneric {
		return t
	}

	bytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return svc.InstrumentableGeneric
	}
	return instrumentableFromEnviron(string(bytes))
}

func resolveProcBinary(pid int32) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	realPath, err := os.Readlink(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to read process binary: %w", err)
	}

	return fmt.Sprintf("/proc/%d/root%s", pid, realPath), nil
}

func findLanguageFromElf(filePath string) svc.InstrumentableType {
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

func collectSymbols(f *elf.File, syms []elf.Symbol, addresses map[string]Sym, symbolNames []string) {
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}
		if !contains(symbolNames, s.Name) {
			continue
		}
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
		addresses[s.Name] = Sym{Off: address, Len: s.Size, Prog: p}
	}
}

func FindExeSymbols(f *elf.File, symbolNames []string) (map[string]Sym, error) {
	addresses := map[string]Sym{}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(f, syms, addresses, symbolNames)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(f, dynsyms, addresses, symbolNames)

	return addresses, nil
}

func matchExeSymbols(ctx *fastelf.ElfContext) svc.InstrumentableType {
	for _, sec := range ctx.Sections {
		if sec.Type != fastelf.SHT_SYMTAB && sec.Type != fastelf.SHT_DYNSYM {
			continue
		}

		if int(sec.Link) >= len(ctx.Sections) {
			continue
		}

		strtab := ctx.Sections[sec.Link]

		if int(strtab.Offset) >= len(ctx.Data) {
			continue
		}

		strs := ctx.Data[strtab.Offset:]

		symCount := int(sec.Size / sec.Entsize)

		for i := range symCount {
			sym := fastelf.ReadStruct[fastelf.Elf64_Sym](ctx.Data, int(sec.Offset)+i*int(sec.Entsize))

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
