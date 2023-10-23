package exec

import (
	"debug/elf"
	"errors"
	"fmt"

	"github.com/grafana/beyla/pkg/internal/svc"
)

func FindProcLanguage(pid int32, elfF *elf.File) svc.InstrumentableType {
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

	if elfF == nil {
		pidPath := fmt.Sprintf("/proc/%d/exe", pid)
		elfF, err = elf.Open(pidPath)

		if err != nil || elfF == nil {
			return svc.InstrumentableGeneric
		}
	}

	return findLanguageFromElf(elfF)
}

func findLanguageFromElf(elfF *elf.File) svc.InstrumentableType {
	gosyms := elfF.Section(".gosymtab")

	if gosyms != nil {
		return svc.InstrumentableGolang
	}

	if allSyms, err := FindExeSymbols(elfF); err == nil {
		for name := range allSyms {
			t := instrumentableFromSymbolName(name)
			if t != svc.InstrumentableGeneric {
				return t
			}
		}
	}

	return svc.InstrumentableGeneric
}

func FindExeSymbols(f *elf.File) (map[string]Sym, error) {
	addresses := map[string]Sym{}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	syms = append(syms, dynsyms...)

	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
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

	return addresses, nil
}
