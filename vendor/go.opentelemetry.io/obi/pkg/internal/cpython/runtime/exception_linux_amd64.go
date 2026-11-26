// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"debug/elf"
	"fmt"
	"slices"

	"golang.org/x/arch/x86/x86asm"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// deriveErrSetObject follows the single local tail jump of the exported
// PyErr_SetObject stub, which fetches the thread state and jumps to the hidden
// _PyErr_SetObject. A CPython 3.13.14 slim build contains:
//
//	258768: call __tls_get_addr@plt
//	25876d: mov  rdx,r12
//	258770: mov  rsi,rbx
//	258777: mov  rdi,[rax+8]           // tstate
//	25877e: jmp  1bc3c0                // _PyErr_SetObject
//
// One of the str setters must call the same target, as PyErr_SetString does:
//
//	1e6a42: call 1bc3c0
//
// It returns the target's file offset.
func deriveErrSetObject(file *elf.File, setObject procs.Sym, callers []procs.Sym) (uint64, error) {
	jumps, err := localTargets(file, setObject, x86asm.JMP)
	if err != nil {
		return 0, err
	}
	if len(jumps) != 1 {
		return 0, fmt.Errorf("%w: PyErr_SetObject has %d local tail jumps", errUnsupportedLayout, len(jumps))
	}
	target := jumps[0]

	confirmed := false
	for _, caller := range callers {
		calls, err := localTargets(file, caller, x86asm.CALL)
		if err != nil {
			return 0, err
		}
		confirmed = confirmed || slices.Contains(calls, target)
	}
	if !confirmed {
		return 0, fmt.Errorf("%w: PyErr_SetString does not call the PyErr_SetObject target", errUnsupportedLayout)
	}

	starts, err := pythonFunctionStarts(file)
	if err != nil {
		return 0, err
	}
	if err := validateCollectorTarget(file, starts, target); err != nil {
		return 0, err
	}
	return strictELFFileOffset(file, target)
}

// localTargets returns the direct, non-PLT targets of one branch opcode in a function.
func localTargets(file *elf.File, function procs.Sym, op x86asm.Op) ([]uint64, error) {
	var targets []uint64
	err := walkInstructions(file, function.Value, function.Len, func(decoded decodedInstruction) error {
		if decoded.inst.Op != op {
			return nil
		}
		if _, direct := decoded.inst.Args[0].(x86asm.Rel); !direct {
			return nil
		}
		target, err := relativeInstructionTarget(decoded)
		if err != nil {
			return err
		}
		if !addressInPLT(file, target) {
			targets = append(targets, target)
		}
		return nil
	})
	return targets, err
}
