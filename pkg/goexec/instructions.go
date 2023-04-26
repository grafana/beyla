package goexec

import (
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/exp/slog"
)

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
	sec := elfF.Section(".gosymtab")
	if sec == nil {
		return nil, errors.New(".gosymtab section not found in target binary, make sure this is a Go application")
	}
	symTabRaw, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("acquiring .gosymtab data: %w", err)
	}
	pcln := gosym.NewLineTable(pclndat, elfF.Section(".text").Addr)
	symTab, err := gosym.NewTable(symTabRaw, pcln)
	if err != nil {
		return nil, fmt.Errorf("decoding .gosymtab: %w", err)
	}
	return symTab, nil
}
