// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"encoding/binary"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

func embeddedSDKActivationAlias(name string) string {
	const pkg = "go.opentelemetry.io/otel/trace."
	for _, receiver := range []string{"noopSpan", "nonRecordingSpan", "(*noopSpan)", "(*nonRecordingSpan)"} {
		suffix := pkg + receiver + ".TracerProvider"
		if prefix, ok := strings.CutSuffix(name, suffix); ok {
			return prefix + pkg + "noopSpan.tracerProvider"
		}
	}
	return ""
}

// embeddedSDKFlagReadOffset finds where to attach the embedded SDK activation
// probe in data, the compiled instructions of a TracerProvider method. It returns
// a byte offset relative to the start of data, or zero if no usable match exists.
//
// The OTel trace package contains an embedded SDK, normally disabled. Its
// autoInstEnabled variable points to a boolean initially set to false.
// noopSpan.TracerProvider passes this pointer to its private tracerProvider
// helper, which chooses between recording and no-op providers:
//
//	if *autoEnabled {
//		return newAutoTracerProvider()
//	}
//	return noopTracerProvider{}
//
// OBI's activation probe writes true through this pointer after the span capture
// probes have attached. OTel 1.35 can inline the helper into public TracerProvider
// methods, leaving no separate helper entry to probe. This fallback recognizes
// the compiled flag check inside those methods. OTel 1.36+ uses //go:noinline on
// the helper, so the normal function-entry probe can be used instead.
//
// A register is temporary storage inside the CPU; [register] means the memory at
// the address it holds. The recognized amd64 instructions are:
//
//	MOV RCX, [RIP+disp] // Load the global pointer into RCX, relative to the code.
//	CMP byte [RCX], 0   // Read the boolean byte and compare it with false (zero).
//	JE disabled        // Jump if the comparison found zero.
//
// On arm64, the equivalent sequence uses a page address to locate the pointer:
//
//	ADRP Xn, page       // Locate the memory page containing the global pointer.
//	LDR X2, [Xn, disp]  // Load that pointer into X2.
//	LDRB W2, [X2]      // Read the boolean byte directly through the pointer.
//	TBZ W2, 0, disabled // Jump if bit zero of the boolean is clear (false).
//
// disp is the compiler-chosen offset used to locate the stored pointer; it can
// vary between builds. amd64 instructions also vary in length, so they must be
// decoded to advance to the next instruction. arm64 instructions are always
// four bytes, so each candidate is a four-instruction window.
//
// Return the offset of CMP or LDRB: the probe runs before that instruction, when
// the pointer has been loaded but the flag has not yet been read. It must be in
// RCX or X2 because the activation probe reads GO_PARAM3, the third Go argument
// register. At the helper entry, noopSpan's embedded interface receiver uses the
// first two argument registers, so autoEnabled is in the third. The inlined
// sequence must leave the pointer in that same register for this probe to work.
// W2 is the lower-width view of X2; writing the byte into W2 overwrites X2's
// pointer. Attaching after LDRB would therefore lose the address needed to write
// the flag. The exact LDRB encoding also excludes reads at an added offset.
//
// Only these recognized sequences produce a probe location. If the compiler
// emits a different sequence, returning zero tells the loader to skip this
// activation hook rather than write through an unverified pointer.
func embeddedSDKFlagReadOffset(machine elf.Machine, data []byte) uint64 {
	if machine == elf.EM_X86_64 {
		for index := 0; index < len(data); {
			load, err := x86asm.Decode(data[index:], 64)
			if err != nil {
				return 0
			}
			index += load.Len
			check, checkErr := x86asm.Decode(data[index:], 64)
			memory, ok := load.Args[1].(x86asm.Mem)
			loadsFlagPointer := load.Op == x86asm.MOV && load.Args[0] == x86asm.RCX && ok &&
				memory.Base == x86asm.RIP && memory.Index == 0 && memory.Segment == 0
			readsFlag := checkErr == nil && check.Op == x86asm.CMP && check.MemBytes == 1 &&
				check.Args[0] == (x86asm.Mem{Base: x86asm.RCX}) && check.Args[1] == x86asm.Imm(0)
			if !loadsFlagPointer || !readsFlag {
				continue
			}

			branch, branchErr := x86asm.Decode(data[index+check.Len:], 64)
			if branchErr == nil && branch.Op == x86asm.JE {
				return uint64(index)
			}
		}
	}
	if machine == elf.EM_AARCH64 {
		const instructionSize = 4
		const flagRead = 0x39400042 // LDRB W2, [X2], without pointer adjustment.
		for index := 0; index+4*instructionSize <= len(data); index += instructionSize {
			page, pageErr := arm64asm.Decode(data[index:])
			load, loadErr := arm64asm.Decode(data[index+instructionSize:])
			branch, branchErr := arm64asm.Decode(data[index+3*instructionSize:])
			memory, ok := load.Args[1].(arm64asm.MemImmediate)
			bit, bitOK := branch.Args[1].(arm64asm.Imm)
			pageRegister, pageOK := page.Args[0].(arm64asm.Reg)
			loadsFlagPointer := pageErr == nil && page.Op == arm64asm.ADRP && pageOK && loadErr == nil &&
				load.Op == arm64asm.LDR && load.Args[0] == arm64asm.X2 && ok &&
				memory.Mode == arm64asm.AddrOffset && memory.Base == arm64asm.RegSP(pageRegister)
			readsFlag := binary.LittleEndian.Uint32(data[index+2*instructionSize:]) == flagRead
			branchesIfDisabled := branchErr == nil && branch.Op == arm64asm.TBZ &&
				branch.Args[0] == arm64asm.W2 && bitOK && bit.Imm == 0
			if loadsFlagPointer && readsFlag && branchesIfDisabled {
				return uint64(index + 2*instructionSize)
			}
		}
	}
	return 0
}
