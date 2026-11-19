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

	"golang.org/x/sys/unix"

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

func FindExeSymbols(f *elf.File, symbolNames []string, types ...elf.SymType) (map[string]Sym, error) {
	wanted := make(map[string]string, len(symbolNames))
	for _, name := range symbolNames {
		if name != "" {
			wanted[name] = name
		}
	}

	return findExeSymbols(f, wanted, nil, types...)
}

// FindExeSymbolsMatching returns the symbols whose name satisfies match, keyed by name.
func FindExeSymbolsMatching(f *elf.File, match func(name string) bool, types ...elf.SymType) (map[string]Sym, error) {
	return findExeSymbols(f, nil, match, types...)
}

func findExeSymbols(f *elf.File, wanted map[string]string, match func(string) bool, types ...elf.SymType) (map[string]Sym, error) {
	addresses := map[string]Sym{}
	if f.SectionByType(elf.SHT_SYMTAB) == nil && f.SectionByType(elf.SHT_DYNSYM) == nil {
		return addresses, nil
	}

	ctx, err := fastelf.NewElfContextFromELF(f)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}

	for _, sectionType := range []uint32{fastelf.SHT_SYMTAB, fastelf.SHT_DYNSYM} {
		for _, section := range ctx.Sections {
			if section == nil || section.Type != sectionType {
				continue
			}

			if section.Size == 0 {
				break
			}

			if section.Link == 0 || uint64(section.Link) >= uint64(len(ctx.Sections)) {
				return nil, errors.New("section has invalid string table link")
			}

			strtab, ok := ctx.SectionData(ctx.Sections[section.Link])
			if !ok {
				return nil, errors.New("invalid string table bounds")
			}

			offset, entrySize, count, ok := ctx.SymbolTableBounds(section)
			if !ok || section.Entsize != elf.Sym64Size || section.Size%section.Entsize != 0 {
				return nil, errors.New("invalid symbol table bounds or entry size")
			}

			populateRange(ctx.Data, ctx.Sections[section.Link].Offset, ctx.Sections[section.Link].Size)
			populateRange(ctx.Data, uint64(offset), uint64(count*entrySize))

			// Symbol tables begin with a reserved null entry.
			for i := 1; i < count; i++ {
				symbol := fastelf.ReadStruct[fastelf.Elf64_Sym](ctx.Data, offset+i*entrySize)
				if !slices.Contains(types, elf.ST_TYPE(symbol.Info)) {
					continue
				}

				name := fastelf.GetCStringUnsafe(strtab, symbol.Name)
				var requested string
				var ok bool
				if match == nil {
					requested, ok = wanted[name]
				} else if match(name) {
					requested, ok = strings.Clone(name), true
				}
				if !ok {
					continue
				}

				addresses[requested] = resolveSymbol(f, elf.Symbol{
					Name: requested, Value: symbol.Value, Size: symbol.Size,
				})
			}
			break
		}
	}
	return addresses, nil
}

// populateRange asks the kernel to read the given range of a mapped file in a
// single batch instead of faulting it in page by page during the scan, which
// is several times faster when the symbol tables are not in the page cache.
// It is best effort: MADV_POPULATE_READ needs Linux 5.14, and failing to
// populate only means the pages are faulted in lazily as before.
func populateRange(data []byte, offset, size uint64) {
	end := offset + size
	if size == 0 || end < offset || end > uint64(len(data)) {
		return
	}

	pageMask := uint64(os.Getpagesize()) - 1

	_ = unix.Madvise(data[offset&^pageMask:end], unix.MADV_POPULATE_READ)
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

	return Sym{Name: s.Name, Off: address, Value: s.Value, Len: s.Size, Prog: p}
}

func matchExeSymbols(ctx *fastelf.ElfContext) svc.InstrumentableType {
	isRust := false

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

			if sym == nil || fastelf.SymType(sym.Info) != fastelf.STT_FUNC ||
				sym.Size == 0 ||
				sym.Value == 0 {
				continue
			}

			name := fastelf.GetCStringUnsafe(strs, sym.Name)

			t := instrumentableFromSymbolName(name)

			if t != svc.InstrumentableGeneric {
				if t == svc.InstrumentableRust {
					isRust = true
				} else {
					return t
				}
			}
		}
	}

	if isRust {
		return svc.InstrumentableRust
	}

	return svc.InstrumentableGeneric
}
