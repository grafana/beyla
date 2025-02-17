package exec

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"

	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

func FindProcLanguage(pid int32, elfF *elf.File, path string) svc.InstrumentableType {
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

	t := findLanguageFromElf(elfF)
	if t != svc.InstrumentableGeneric {
		return t
	}

	t = instrumentableFromPath(path)
	if t != svc.InstrumentableGeneric {
		return t
	}

	bytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return svc.InstrumentableGeneric
	}
	return instrumentableFromEnviron(string(bytes))
}

func findLanguageFromElf(elfF *elf.File) svc.InstrumentableType {
	gosyms := elfF.Section(".gosymtab")

	if gosyms != nil {
		return svc.InstrumentableGolang
	}

	return matchExeSymbols(elfF)
}

func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}

	return false
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

func matchSymbols(syms []elf.Symbol) svc.InstrumentableType {
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}
		t := instrumentableFromSymbolName(s.Name)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	return svc.InstrumentableGeneric
}

func matchExeSymbols(f *elf.File) svc.InstrumentableType {
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return svc.InstrumentableGeneric
	}

	t := matchSymbols(syms)
	if t != svc.InstrumentableGeneric {
		return t
	}

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return svc.InstrumentableGeneric
	}

	return matchSymbols(dynsyms)
}
