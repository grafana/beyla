package goexec

import (
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
)

func isSupportedGoBinary(elfF *elf.File) error {
	goVersion, _, err := getGoDetails(elfF)

	if err == nil && !supportedGoVersion(goVersion) {
		return fmt.Errorf("unsupported Go version: %v. Minimum supported version is %v", goVersion, minGoVersion)
	}

	return nil
}

// instrumentationPoints loads the provided executable and looks for the addresses
// where the start and return probes must be inserted.
//
//nolint:cyclop
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

	if err = isSupportedGoBinary(elfF); err != nil {
		return nil, err
	}

	gosyms := elfF.Section(".gosymtab")

	var allSyms map[string]exec.Sym

	// no go symbols in the executable, maybe it's statically linked
	// find regular elf symbols
	if gosyms == nil {
		allSyms, _ = exec.FindExeSymbols(elfF, funcNames)
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
			if gosyms == nil && len(allSyms) > 0 {
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

func handleStaticSymbol(fName string, allOffsets map[string]FuncOffsets, allSyms map[string]exec.Sym, ilog *slog.Logger) {
	s, ok := allSyms[fName]

	if ok && s.Prog != nil {
		data := make([]byte, s.Len)
		_, err := s.Prog.ReadAt(data, int64(s.Off-s.Prog.Off))
		if err != nil {
			ilog.Error("error reading instructions for symbol", "symbol", fName, "error", err)
			return
		}

		returns, err := FindReturnOffsets(s.Off, data)
		if err != nil {
			ilog.Error("error finding returns for symbol", "symbol", fName, "offset", s.Off-s.Prog.Off, "size", s.Len, "error", err)
			return
		}
		allOffsets[fName] = FuncOffsets{Start: s.Off, Returns: returns}
	} else {
		ilog.Debug("can't find in elf symbol table", "symbol", fName, "ok", ok, "prog", s.Prog)
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

			returns, err := FindReturnOffsets(off, data)
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

	// Borrowed from OpenTelemetry Go Auto-Instrumentation
	// we extract the `textStart` value based on the header of the pclntab,
	// this is used to parse the line number table, and is not necessarily the start of the `.text` section.
	// when a binary is built with C code, the value of `textStart` is not the same as the start of the `.text` section.
	// https://github.com/golang/go/blob/master/src/runtime/symtab.go#L374
	var runtimeText uint64

	if len(pclndat) > 8*2*8 {
		ptrSize := uint32(pclndat[7])
		switch ptrSize {
		case 4:
			runtimeText = uint64(binary.LittleEndian.Uint32(pclndat[8+2*ptrSize:]))
		case 8:
			runtimeText = binary.LittleEndian.Uint64(pclndat[8+2*ptrSize:])
		default:
			return nil, errors.New("unknown .gopclntab text ptr size")
		}
	} else {
		txtSection := elfF.Section(".text")
		if txtSection == nil {
			return nil, errors.New("can't find .text section in ELF file")
		}
		runtimeText = txtSection.Addr
	}

	pcln := gosym.NewLineTable(pclndat, runtimeText)
	// First argument accepts the .gosymtab ELF section.
	// Since Go 1.3, .gosymtab is empty so we just pass an nil slice
	symTab, err := gosym.NewTable(nil, pcln)
	if err != nil {
		return nil, fmt.Errorf("creating go symbol table: %w", err)
	}
	return symTab, nil
}
