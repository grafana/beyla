package goexec

import (
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"fmt"

	"golang.org/x/exp/slog"
)

// instrumentationPoints loads the provided executable and looks for the addresses
// where the start and return probes must be inserted.
// TODO: allow instrumenting multiple functions sharing the same interface
func instrumentationPoints(elfF *elf.File, funcName string) (FuncOffsets, error) {
	log := slog.With("component", "goexec.InstrumentationPoint", "funcName", funcName)
	dwarfInfo, err := elfF.DWARF()
	if err != nil {
		return FuncOffsets{}, fmt.Errorf("can't load DWARF information from ELF file: %w", err)
	}
	entryReader := dwarfInfo.Reader()
	for {
		entry, err := entryReader.Next()
		if entry == nil || err != nil {
			log.Info("reaching end of dwarf symbols")
			break
		}
		var lowAddr uint64
		functionFound := false

	fieldsIter:
		for _, field := range entry.Field {
			switch field.Attr {
			case dwarf.AttrName:
				// TODO: make it working for other functions
				if field.Val == funcName {
					functionFound = true
					continue
				} else {
					break fieldsIter
				}
			case dwarf.AttrLowpc:
				lowAddr = field.Val.(uint64)
			}
		}
		if functionFound {
			// seems that this is not really needed, neither fieldsIter then
			slog.Debug("found instrumentable function", "address", fmt.Sprintf("0x%x", lowAddr))
			var pclndat []byte
			if sec := elfF.Section(".gopclntab"); sec != nil {
				pclndat, err = sec.Data()
				if err != nil {
					return FuncOffsets{}, fmt.Errorf("acquiring .gopclntab section data: %w", err)
				}
			}
			sec := elfF.Section(".gosymtab")
			if sec == nil {
				return FuncOffsets{}, fmt.Errorf(".gosymtab section not found in target binary, make sure this is a Go application")
			}
			symTabRaw, err := sec.Data()
			if err != nil {
				return FuncOffsets{}, fmt.Errorf("getting memory section data: %w", err)
			}
			pcln := gosym.NewLineTable(pclndat, elfF.Section(".text").Addr)
			symTab, err := gosym.NewTable(symTabRaw, pcln)
			if err != nil {
				return FuncOffsets{}, fmt.Errorf("can't decode symbols table: %w", err)
			}

			for _, f := range symTab.Funcs {
				if f.Name == funcName {
					log.Debug("found target function")
					start, returns, err := findFuncOffset(&f, elfF)
					if err != nil {
						return FuncOffsets{}, err
					}
					log.Debug("found relevant function for instrumentation", "function", f.Name,
						"startOffset", start, "returnsOffsets", returns)
					return FuncOffsets{
						Start:   start,
						Returns: returns,
					}, nil
				}
			}
		}
	}
	return FuncOffsets{}, fmt.Errorf("couldn't find function %q", funcName)
}

func findFuncOffset(f *gosym.Func, elfF *elf.File) (uint64, []uint64, error) {
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
				return 0, nil, fmt.Errorf("finding function return: %w", err)
			}

			returns, err := findReturnOffssets(off, data)
			if err != nil {
				return 0, nil, fmt.Errorf("finding function return: %w", err)
			}
			// TODO: not return on first match but append all the offsets of all the programs
			return off, returns, nil
		}

	}

	return 0, nil, fmt.Errorf("prog not found")
}
