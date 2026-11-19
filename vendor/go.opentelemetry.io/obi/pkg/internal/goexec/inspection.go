// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"sync"

	"go.opentelemetry.io/obi/internal/goabi"
)

// inspection shares what one lookup on an executable derives between its
// steps, so that DWARF is parsed, and the runtime ABI and moduledata are
// resolved, at most once. It must not outlive that lookup.
type inspection struct {
	elf *elf.File
	// loadDWARF is elf.File.DWARF; tests replace it to count the parses.
	loadDWARF func() (*dwarf.Data, error)
	// runtimeABIOnly makes the DWARF parse leave out the struct member offsets.
	runtimeABIOnly bool

	dwarf      func() dwarfFacts
	runtimeABI func() (goabi.ABI, error)
	moduledata func() (runtimeModuledata, error)
}

// dwarfFacts holds what the runtime ABI and struct member lookups read from
// DWARF. Both read the same parse, which is then released instead of being
// kept in memory while the Go symbol table is built.
type dwarfFacts struct {
	err           error
	runtimeABI    goabi.ABI
	runtimeABIErr error
	fieldOffsets  FieldOffsets
	missingFields map[GoOffset]struct{}
}

// runtimeModuledata is the address of an executable's runtime.firstmoduledata
// and the start of its Go text.
type runtimeModuledata struct {
	addr uint64
	text uint64
}

func newInspection(ef *elf.File) *inspection {
	in := &inspection{elf: ef, loadDWARF: ef.DWARF}
	in.dwarf = sync.OnceValue(in.readDWARFFacts)
	in.runtimeABI = sync.OnceValues(in.loadRuntimeABI)
	in.moduledata = sync.OnceValues(in.findModuledata)
	return in
}

// standaloneModuledata locates moduledata for a caller outside InspectOffsets.
// That lookup reads nothing but the runtime ABI from DWARF, so the parse skips
// the struct member offsets.
func standaloneModuledata(ef *elf.File) (runtimeModuledata, error) {
	in := newInspection(ef)
	in.runtimeABIOnly = true
	return in.moduledata()
}

func (in *inspection) readDWARFFacts() dwarfFacts {
	data, err := in.loadDWARF()
	if err != nil {
		return dwarfFacts{err: err}
	}

	var facts dwarfFacts
	if !in.runtimeABIOnly {
		facts.fieldOffsets, facts.missingFields = structMemberOffsetsFromDwarf(data)
	}
	if targetVersion, ok := runtimeABIVersion(in.elf); ok {
		facts.runtimeABI, facts.runtimeABIErr = goabi.Extract(data, targetVersion)
	}
	return facts
}

// loadRuntimeABI reads the runtime ABI of the executable's Go version from the
// shared DWARF parse, or from the generated offsets if DWARF does not have it.
func (in *inspection) loadRuntimeABI() (goabi.ABI, error) {
	targetVersion, ok := runtimeABIVersion(in.elf)
	if !ok {
		return goabi.ABI{}, errors.New("the Go version of the executable has no runtime type metadata ABI")
	}
	return resolveGoRuntimeABI(
		func() (goabi.ABI, error) {
			facts := in.dwarf()
			if facts.err != nil {
				return goabi.ABI{}, facts.err
			}
			return facts.runtimeABI, facts.runtimeABIErr
		},
		func() (goabi.ABI, error) {
			return loadGeneratedGoRuntimeABI(targetVersion)
		},
	)
}
