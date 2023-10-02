package goexec

import (
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

type sym struct {
	off  uint64
	len  uint64
	prog *elf.Prog
}

// instrumentationPoints loads the provided executable and looks for the addresses
// where the start and return probes must be inserted.
func instrumentationPoints(elfF *elf.File, funcNames []string) (map[string]FuncOffsets, error) {
	ilog := slog.With("component", "goexec.instructions")
	ilog.Debug("searching for instrumentation points", "functions", funcNames)
	functions := map[string]struct{}{}
	for _, fn := range funcNames {
		functions[fn] = struct{}{}
	}
	symTab, err := findGoSymbolTable(elfF)
	if err != nil {
		return nil, err
	}

	gosyms := elfF.Section(".gosymtab")

	var allSyms map[string]sym

	// no go symbols in the executable, maybe it's statically linked
	// find regular elf symbols
	if gosyms == nil {
		allSyms, err = findExeSymbols(elfF)
		if err != nil {
			return nil, err
		}
	}

	// check which functions in the symbol table correspond to any of the functions
	// that we are looking for, and find their offsets
	allOffsets := map[string]FuncOffsets{}
	for _, f := range symTab.Funcs {
		fName := f.Name
		// fetch short path of function for vendor scene
		if paths := strings.Split(fName, "/vendor/"); len(paths) > 1 {
			fName = paths[1]
		}

		if _, ok := functions[fName]; ok {
			// when we don't have a Go symbol table, the executable is statically linked, we don't look for offsets
			// using the gosym tab, we lookup offsets just like a regular elf file.
			// we still need to find the return statements, since go linkage is non-standard we can't use uretprobe
			if gosyms == nil {
				handleStaticSymbol(fName, allOffsets, allSyms, ilog)
				continue
			}

			offs, ok, err := findFuncOffset(&f, elfF)
			if err != nil {
				return nil, err
			}
			if ok {
				ilog.Debug("found relevant function for instrumentation", "function", fName, "offsets", offs)
				allOffsets[fName] = offs
			}
		}
	}

	return allOffsets, nil
}

func handleStaticSymbol(fName string, allOffsets map[string]FuncOffsets, allSyms map[string]sym, ilog *slog.Logger) {
	s, ok := allSyms[fName]

	if ok && s.prog != nil {
		data := make([]byte, s.len)
		_, err := s.prog.ReadAt(data, int64(s.off-s.prog.Off))
		if err != nil {
			ilog.Error("error reading instructions for symbol", "symbol", fName, "error", err)
			return
		}

		returns, err := findReturnOffssets(s.off, data)
		if err != nil {
			ilog.Error("error finding returns for symbol", "symbol", fName, "offset", s.off-s.prog.Off, "size", s.len, "error", err)
			return
		}
		allOffsets[fName] = FuncOffsets{Start: s.off, Returns: returns}
	} else {
		ilog.Debug("can't find in elf symbol table", "symbol", fName, "ok", ok, "prog", s.prog)
	}
}

// findFuncOffset gets the start address and end addresses of the function whose symbol is passed
func findFuncOffset(f *gosym.Func, elfF *elf.File) (FuncOffsets, bool, error) {
	for _, prog := range elfF.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		// For more info on this calculation: stackoverflow.com/a/40249502
		if prog.Vaddr <= f.Value && f.Value < (prog.Vaddr+prog.Memsz) {
			off := f.Value - prog.Vaddr + prog.Off

			funcLen := f.End - f.Entry
			data := make([]byte, funcLen)
			_, err := prog.ReadAt(data, int64(f.Value-prog.Vaddr))
			if err != nil {
				return FuncOffsets{}, false, fmt.Errorf("finding function return: %w", err)
			}

			returns, err := findReturnOffssets(off, data)
			if err != nil {
				return FuncOffsets{}, false, fmt.Errorf("finding function return: %w", err)
			}
			return FuncOffsets{Start: off, Returns: returns}, true, nil
		}
	}

	return FuncOffsets{}, false, nil
}

func findGoSymbolTable(elfF *elf.File) (*gosym.Table, error) {
	var err error
	var pclndat []byte
	// program counter line table
	if sec := elfF.Section(".gopclntab"); sec != nil {
		if pclndat, err = sec.Data(); err != nil {
			return nil, fmt.Errorf("acquiring .gopclntab data: %w", err)
		}
	}
	pcln := gosym.NewLineTable(pclndat, elfF.Section(".text").Addr)
	// First argument accepts the .gosymtab ELF section.
	// Since Go 1.3, .gosymtab is empty so we just pass an nil slice
	symTab, err := gosym.NewTable(nil, pcln)
	if err != nil {
		return nil, fmt.Errorf("creating go symbol table: %w", err)
	}
	return symTab, nil
}

func findExeSymbols(f *elf.File) (map[string]sym, error) {
	addresses := map[string]sym{}
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
		addresses[s.Name] = sym{off: address, len: s.Size, prog: p}
	}

	return addresses, nil
}
