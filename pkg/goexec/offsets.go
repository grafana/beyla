// Package goexec helps analyzing Go executables
package goexec

import (
	"fmt"
)

type Offsets struct {
	FileInfo FileInfo
	Funcs    map[string][]FuncOffsets
	Field    FieldOffsets
}

type FuncOffsets struct {
	Start   uint64
	Returns []uint64
}

type FieldOffsets map[string]any

// InspectOffsets gets the memory addresses/offsets of the instrumenting function, as well as the required
// parameters fields to be read from the eBPF code
func InspectOffsets(execFile string, funcs map[string][]string) (Offsets, error) {
	// Analyse executable ELF file and find instrumentation points
	execElf, err := findExecELF(execFile)
	if err != nil {
		return Offsets{}, fmt.Errorf("looking for %s executable ELF: %w", execFile, err)
	}
	defer execElf.ELF.Close()

	foundOffsets := make(map[string][]FuncOffsets)

	for section, funcNames := range funcs {
		// check the function instrumentation points
		found, err := instrumentationPoints(execElf.ELF, funcNames)
		if err != nil {
			log.Warn("Unable to find instrumentation points in file %s: for %s - %w", execFile, section, err)
		}
		foundOffsets[section] = found
	}

	// check the offsets of the required fields from the method arguments
	structFieldOffsets, err := structMemberOffsets(execElf.ELF)
	if err != nil {
		return Offsets{}, fmt.Errorf("checking struct members in file %s: %w", execFile, err)
	}

	return Offsets{
		FileInfo: execElf,
		Funcs:    foundOffsets,
		Field:    structFieldOffsets,
	}, nil
}
