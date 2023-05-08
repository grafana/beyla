// Package goexec helps analyzing Go executables
package goexec

import (
	"context"
	"fmt"
)

type Offsets struct {
	FileInfo FileInfo
	// Funcs key: function name
	Funcs map[string]FuncOffsets
	Field FieldOffsets
}

type FuncOffsets struct {
	Start   uint64
	Returns []uint64
}

type FieldOffsets map[string]any

// InspectOffsets gets the memory addresses/offsets of the instrumenting function, as well as the required
// parameters fields to be read from the eBPF code
func InspectOffsets(ctx context.Context, finder ProcessFinder, funcs []string) (*Offsets, error) {
	// Analyse executable ELF file and find instrumentation points
	execElf, err := findExecELF(ctx, finder)
	if err != nil {
		return nil, fmt.Errorf("looking for executable ELF: %w", err)
	}
	defer execElf.ELF.Close()

	found, err := instrumentationPoints(execElf.ELF, funcs)
	if err != nil {
		return nil, fmt.Errorf("finding instrumentation points: %w", err)
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("couldn't find any instrumentation point in %s", execElf.CmdExePath)
	}

	// check the offsets of the required fields from the method arguments
	structFieldOffsets, err := structMemberOffsets(execElf.ELF)
	if err != nil {
		return nil, fmt.Errorf("checking struct members in file %s: %w", execElf.ProExeLinkPath, err)
	}

	return &Offsets{
		FileInfo: execElf,
		Funcs:    found,
		Field:    structFieldOffsets,
	}, nil
}
