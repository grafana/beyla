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
func InspectOffsets(finder ProcessFinder, funcs map[string][]string) (Offsets, error) {
	// Analyse executable ELF file and find instrumentation points
	execElf, err := findExecELF(finder)
	if err != nil {
		return Offsets{}, fmt.Errorf("looking for executable ELF: %w", err)
	}
	defer execElf.ELF.Close()

	foundOffsets := make(map[string][]FuncOffsets)

	for section, funcNames := range funcs {
		// check the function instrumentation points
		found, err := instrumentationPoints(execElf.ELF, funcNames)
		if err != nil {
			log().Debug("Unable to find instrumentation points", "section", section, "message", err)
		}
		foundOffsets[section] = found
	}

	// check the offsets of the required fields from the method arguments
	structFieldOffsets, err := structMemberOffsets(execElf.ELF)
	if err != nil {
		return Offsets{}, fmt.Errorf("checking struct members in file %s: %w", execElf.ProExeLinkPath, err)
	}

	return Offsets{
		FileInfo: execElf,
		Funcs:    foundOffsets,
		Field:    structFieldOffsets,
	}, nil
}
