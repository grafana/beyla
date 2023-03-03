// Package goexec helps analyzing Go executables
package goexec

import "fmt"

type Offsets struct {
	FileInfo FileInfo
	Func     FuncOffsets
	Field    FieldOffsets
}

type FuncOffsets struct {
	Start   uint64
	Returns []uint64
}

type FieldOffsets map[string]any

// InspectOffsets gets the memory addresses/offsets of the instrumenting function, as well as the required
// parameters fields to be read from the eBPF code
func InspectOffsets(execFile, funcName string) (Offsets, error) {
	// Analyse executable ELF file and find instrumentation points
	execElf, err := findExecELF(execFile)
	if err != nil {
		return Offsets{}, fmt.Errorf("looking for %s executable ELF: %w", execFile, err)
	}
	defer execElf.ELF.Close()

	// check the function instrumentation points
	funcOffsets, err := instrumentationPoints(execElf.ELF, funcName)
	if err != nil {
		return Offsets{}, fmt.Errorf("searching for instrumentation points for func %s in file %s: %w",
			funcName, execFile, err)
	}

	// check the offsets of the required fields from the method arguments
	dwarf, err := execElf.ELF.DWARF()
	if err != nil {
		return Offsets{}, fmt.Errorf("searching for DWARF info in file %s: %w", execFile, err)
	}
	structFieldOffsets, err := structMemberOffsetsFromDwarf(dwarf)
	if err != nil {
		return Offsets{}, fmt.Errorf("checking struct members in file %s: %w", execFile, err)
	}

	return Offsets{
		FileInfo: execElf,
		Func:     funcOffsets,
		Field:    structFieldOffsets,
	}, nil
}
