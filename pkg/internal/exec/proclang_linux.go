package exec

import (
	"debug/elf"
	"errors"
	"fmt"
	"strings"

	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

func FindProcLanguage(pid int32, elfF *elf.File) string {
	maps, err := FindLibMaps(pid)

	if err != nil {
		return ""
	}

	for _, m := range maps {
		if strings.Contains(m.Pathname, "libcoreclr.so") {
			return semconv.TelemetrySDKLanguageDotnet.Value.AsString()
		} else if strings.Contains(m.Pathname, "libjvm.so") {
			return semconv.TelemetrySDKLanguageJava.Value.AsString()
		} else if strings.HasSuffix(m.Pathname, "/node") {
			return semconv.TelemetrySDKLanguageNodejs.Value.AsString()
		} else if strings.HasSuffix(m.Pathname, "/ruby") {
			return semconv.TelemetrySDKLanguageRuby.Value.AsString()
		} else if strings.Contains(m.Pathname, "/python") {
			return semconv.TelemetrySDKLanguagePython.Value.AsString()
		}
	}

	if elfF == nil {
		pidPath := fmt.Sprintf("/proc/%d/exe", pid)
		elfF, err = elf.Open(pidPath)

		if err != nil || elfF == nil {
			return ""
		}
	}

	return findLanguageFromElf(elfF)
}

func findLanguageFromElf(elfF *elf.File) string {
	gosyms := elfF.Section(".gosymtab")

	if gosyms != nil {
		return semconv.TelemetrySDKLanguageGo.Value.AsString()
	}

	if allSyms, err := FindExeSymbols(elfF); err == nil {
		for name := range allSyms {
			if strings.Contains(name, "rust_panic") {
				return "rust"
			} else if strings.HasPrefix(name, "JVM_") || strings.HasPrefix(name, "graal_") {
				return semconv.TelemetrySDKLanguageJava.Value.AsString()
			}
		}
	}

	return ""
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
