// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type decodedInstruction struct {
	address uint64
	inst    x86asm.Inst
}

const (
	// maximumPythonFunctionSize bounds decoder work on malformed or unexpected ELF metadata.
	maximumPythonFunctionSize      = 512
	maximumPythonFunctionTableSize = 64 << 20
	ehFrameEncodedFieldSize        = 4
	ehFrameHeaderSize              = 12
	ehFrameTableEntrySize          = 2 * ehFrameEncodedFieldSize
)

var (
	supportedEHFrameHeaderEncoding = [...]byte{1, 0x1b, 0x03, 0x3b}
	endBranch64Encoding            = [...]byte{0xf3, 0x0f, 0x1e, 0xfa}
	errIndirectCall                = fmt.Errorf("%w: indirect CPython call", errUnsupportedLayout)
)

// boundedFunctionSize uses the next function start as the current function's scan boundary.
func boundedFunctionSize(starts []uint64, start uint64) (uint64, error) {
	index, found := slices.BinarySearch(starts, start)
	if !found || index+1 == len(starts) {
		return 0, fmt.Errorf("%w: missing CPython function boundary", errUnsupportedLayout)
	}
	size := starts[index+1] - start
	if size == 0 || size > maximumPythonFunctionSize {
		return 0, fmt.Errorf("%w: invalid CPython function boundary", errUnsupportedLayout)
	}
	return size, nil
}

// pythonFunctionStartEntries reads the fixed-format search table from .eh_frame_hdr.
func pythonFunctionStartEntries(file *elf.File) (uint64, []byte, error) {
	section := file.Section(".eh_frame_hdr")
	if section == nil || section.ReaderAt == nil || section.Size > maximumPythonFunctionTableSize || file.ByteOrder == nil {
		return 0, nil, fmt.Errorf("%w: missing CPython function-start table", errUnsupportedLayout)
	}
	data := make([]byte, section.Size)
	if _, err := section.ReadAt(data, 0); err != nil {
		return 0, nil, err
	}
	// The header contains four encoding bytes, a 4-byte .eh_frame pointer, and a 4-byte entry count.
	// These encodings select version 1, PC-relative sdata4, udata4, and data-relative sdata4.
	if len(data) < ehFrameHeaderSize ||
		!bytes.Equal(data[:len(supportedEHFrameHeaderEncoding)], supportedEHFrameHeaderEncoding[:]) {
		return 0, nil, fmt.Errorf("%w: unsupported CPython function-start table", errUnsupportedLayout)
	}
	count := uint64(file.ByteOrder.Uint32(data[ehFrameHeaderSize-ehFrameEncodedFieldSize : ehFrameHeaderSize]))
	if count == 0 || ehFrameHeaderSize+count*ehFrameTableEntrySize != uint64(len(data)) {
		return 0, nil, fmt.Errorf("%w: malformed CPython function-start table", errUnsupportedLayout)
	}
	return section.Addr, data[ehFrameHeaderSize:], nil
}

// pythonFunctionStarts decodes and sorts the function addresses indexed by .eh_frame_hdr.
// The matchers use them to recognize local call targets and bound each instruction scan.
func pythonFunctionStarts(file *elf.File) ([]uint64, error) {
	base, entries, err := pythonFunctionStartEntries(file)
	if err != nil {
		return nil, err
	}
	starts := make([]uint64, 0, len(entries)/ehFrameTableEntrySize)
	for offset := 0; offset < len(entries); offset += ehFrameTableEntrySize {
		// Each entry pairs a signed function-start displacement with its unwind-record displacement.
		delta := int32(file.ByteOrder.Uint32(entries[offset : offset+ehFrameEncodedFieldSize]))
		start, err := addRelative(base, int64(delta))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid CPython function start", errUnsupportedLayout)
		}
		starts = append(starts, start)
	}
	slices.Sort(starts)
	for index := 1; index < len(starts); index++ {
		if starts[index] == starts[index-1] {
			return nil, fmt.Errorf("%w: duplicate CPython function start", errUnsupportedLayout)
		}
	}
	return starts, nil
}

// findPrivateCollectorProbe resolves a return probe for CPython's internal GC function.
// It uses a visible collect or gc_collect_main symbol when available, then uses the exported
// PyGC_Collect anchor to derive the hidden function in stripped builds.
func findPrivateCollectorProbe(file *elf.File, version pythonVersion) (GCCompletionProbe, error) {
	if file == nil || file.Machine != elf.EM_X86_64 {
		return GCCompletionProbe{}, fmt.Errorf("%w: invalid CPython ELF", errUnsupportedLayout)
	}
	target, err := privateCollectorSymbolAddress(file)
	if err == nil {
		fileOffset, err := strictELFFileOffset(file, target)
		if err != nil {
			return GCCompletionProbe{}, err
		}
		return GCCompletionProbe{
			Kind:       GCCompletionProbePrivateReturn,
			Source:     GCCompletionProbeSourceSymbol,
			FileOffset: fileOffset,
		}, nil
	}

	// A stripped libpython retains the exported anchor used to start the disassembly walk:
	//
	//	(gdb) info address PyGC_Collect
	//	Symbol "PyGC_Collect" is at 0x268140.
	symbols, err := procs.FindExeSymbols(file, []string{"PyGC_Collect"}, elf.STT_FUNC)
	if err != nil {
		return GCCompletionProbe{}, err
	}
	pyGC, found := symbols["PyGC_Collect"]
	if !found {
		return GCCompletionProbe{}, fmt.Errorf("%w: missing PyGC_Collect anchor", errUnsupportedLayout)
	}
	return derivePrivateCollectorProbe(file, version, pyGC.Value, pyGC.Len)
}

// derivePrivateCollectorProbe converts the exported PyGC_Collect anchor into a return probe
// on the hidden collect or gc_collect_main function whose return follows CPython's GC
// counter updates. It reads function boundaries from .eh_frame_hdr, applies the version's
// disassembly matcher, then converts the matched virtual address to an executable file offset.
func derivePrivateCollectorProbe(
	file *elf.File,
	version pythonVersion,
	pyGCAddress, pyGCSize uint64,
) (GCCompletionProbe, error) {
	if pyGCSize == 0 || pyGCSize > maximumPythonFunctionSize {
		return GCCompletionProbe{}, fmt.Errorf("%w: invalid PyGC_Collect bounds", errUnsupportedLayout)
	}
	starts, err := pythonFunctionStarts(file)
	if err != nil {
		return GCCompletionProbe{}, err
	}
	var target uint64
	switch {
	case version.major == 3 && version.minor >= 9 && version.minor <= 12:
		target, err = collectorFromRepeatedCallShape(file, starts, pyGCAddress, pyGCSize)
	case version.major == 3 && version.minor >= 13 && version.minor <= 14:
		target, err = collectorFromThreadStateCallShape(file, starts, pyGCAddress, pyGCSize)
	default:
		return GCCompletionProbe{}, fmt.Errorf("%w: CPython %s collector shape", errUnsupportedLayout, version)
	}
	if err != nil {
		return GCCompletionProbe{}, err
	}
	fileOffset, err := strictELFFileOffset(file, target)
	if err != nil {
		return GCCompletionProbe{}, err
	}
	return GCCompletionProbe{
		Kind:       GCCompletionProbePrivateReturn,
		Source:     GCCompletionProbeSourceDerived,
		FileOffset: fileOffset,
	}, nil
}

type tlsLookupStage uint8

const (
	tlsLookupIdle tlsLookupStage = iota
	tlsAddressLoaded
	tlsCallComplete
)

type threadStateCallMatchState struct {
	tlsStage                                tlsLookupStage
	thread                                  x86asm.Reg
	hasThread, rdiReady, rsiReady, rdxReady bool
	reachable                               bool
}

// collectorFromThreadStateCallShape resolves the private collector called with
// the current thread state, generation 2, and the manual-collection reason.
// A CPython 3.13.14 slim PyGC_Collect contains this disassembly:
//
//	26814e: lea  rdi,[rip+...]          // thread-local storage descriptor
//	268155: call __tls_get_addr@plt
//	26815a: mov  rbx,[rax+8]            // current PyThreadState
//	...
//	268178: mov  rdi,rbx                // tstate
//	26817b: mov  edx,2                  // manual-collection reason
//	268184: mov  esi,2                  // oldest generation
//	268189: call 1a39a0                 // hidden gc_collect_main
func collectorFromThreadStateCallShape(
	file *elf.File,
	starts []uint64,
	root, rootSize uint64,
) (uint64, error) {
	// Track which parts of the disassembly pattern have been proven at the current instruction.
	state := threadStateCallMatchState{reachable: true}
	// Preserve the state at each forward branch target until the linear scan reaches it.
	// CPython 3.14 jumps over an early return into the collector path:
	//
	//	2b7f1a: jne 2b7f30
	//	... early return ...
	//	> 2b7f30: mov rdi,rbx  // collector path, with rbx still holding tstate
	branchStates := map[uint64]threadStateCallMatchState{}
	var candidates []uint64
	err := walkInstructions(file, root, rootSize, func(decoded decodedInstruction) error {
		// Restore the facts saved when a forward branch reaches this instruction.
		if branchState, found := branchStates[decoded.address]; found {
			delete(branchStates, decoded.address)
			if state.reachable && state != branchState {
				return fmt.Errorf("%w: conflicting CPython collector branch state", errUnsupportedLayout)
			}
			if !state.reachable {
				state = branchState
			}
		}
		candidate, found, err := matchThreadStateCallInstruction(
			file,
			decoded,
			root+rootSize,
			&state,
			branchStates,
		)
		if err != nil {
			return err
		}
		if found {
			candidates = append(candidates, candidate)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if len(candidates) != 1 {
		return 0, fmt.Errorf("%w: CPython thread-state collector did not resolve uniquely", errUnsupportedLayout)
	}
	target := candidates[0]
	if err := validateCollectorTarget(file, starts, target); err != nil {
		return 0, err
	}
	return target, nil
}

// matchThreadStateCallInstruction advances the thread-state and collector-argument match
// by one decoded instruction and returns a fully matched collector call target.
func matchThreadStateCallInstruction(
	file *elf.File,
	decoded decodedInstruction,
	end uint64,
	state *threadStateCallMatchState,
	branchStates map[uint64]threadStateCallMatchState,
) (uint64, bool, error) {
	if !state.reachable {
		return 0, false, nil
	}
	inst := decoded.inst
	// Match the direct PLT call in the TLS lookup sequence.
	//
	//	26814e: lea rdi,[rip+...]
	//	> 268155: call __tls_get_addr@plt
	//	26815a: mov rbx,[rax+8]
	if state.tlsStage == tlsAddressLoaded {
		if inst.Op == x86asm.CALL {
			target, err := relativeInstructionTarget(decoded)
			if err != nil {
				return 0, false, err
			}
			if addressInPLT(file, target) {
				state.tlsStage = tlsCallComplete
				return 0, false, nil
			}
		}
		state.tlsStage = tlsLookupIdle
	}
	// The TLS lookup returns its block in RAX; the thread-state displacement depends on the build.
	//
	//	26814e: lea rdi,[rip+...]
	//	268155: call __tls_get_addr@plt
	//	> 26815a: mov rbx,[rax+8]
	if state.tlsStage == tlsCallComplete {
		destination, register := inst.Args[0].(x86asm.Reg)
		source, memory := inst.Args[1].(x86asm.Mem)
		if inst.Op == x86asm.MOV && register && memory &&
			source.Base == x86asm.RAX && source.Index == 0 {
			state.tlsStage = tlsLookupIdle
			state.thread = destination
			state.hasThread = true
			return 0, false, nil
		}
		state.tlsStage = tlsLookupIdle
	}
	// Start the TLS lookup at a RIP-relative descriptor loaded into RDI.
	//
	//	> 26814e: lea rdi,[rip+...]
	//	268155: call __tls_get_addr@plt
	//	26815a: mov rbx,[rax+8]
	if !state.hasThread {
		destination, register := inst.Args[0].(x86asm.Reg)
		source, memory := inst.Args[1].(x86asm.Mem)
		if inst.Op == x86asm.LEA && register && destination == x86asm.RDI &&
			memory && source.Base == x86asm.RIP {
			state.tlsStage = tlsAddressLoaded
		}
	}
	// A local call with tstate, generation 2, and reason 2 ready is gc_collect_main.
	// PLT calls are external helpers and remain part of the path leading to that call.
	//
	//	268178: mov rdi,rbx
	//	26817b: mov edx,2
	//	268184: mov esi,2
	//	> 268189: call 1a39a0
	if inst.Op == x86asm.CALL {
		target, err := relativeInstructionTarget(decoded)
		if err != nil {
			return 0, false, err
		}
		plt := addressInPLT(file, target)
		complete := state.hasThread && state.rdiReady && state.rsiReady && state.rdxReady
		state.rdiReady, state.rsiReady, state.rdxReady = false, false, false
		if complete && !plt {
			state.hasThread = false
			return target, true, nil
		}
		// A PLT helper preserves tstate only when its register is callee-saved by the ABI.
		//
		//	2b7f30: mov rdi,rbx
		//	> 2b7f33: call _PyErr_GetRaisedException@plt
		//	2b7f38: mov rdi,rbx
		if state.hasThread && (!plt || !threadStateSurvivesCall(state.thread)) {
			state.hasThread = false
		}
		return 0, false, nil
	}
	// Across a branch, preserve the tracked tstate and clear partial instruction sequences.
	//
	//	2b7f18: test eax,eax
	//	> 2b7f1a: jne 2b7f30
	//	2b7f1c: add rsp,0x10
	if branch, unconditional := branchInstruction(inst); branch {
		state.tlsStage = tlsLookupIdle
		state.rdiReady, state.rsiReady, state.rdxReady = false, false, false
		target, err := relativeInstructionTarget(decoded)
		if err != nil {
			return 0, false, err
		}
		if target > decoded.address && target < end {
			if previous, found := branchStates[target]; found && previous != *state {
				return 0, false, fmt.Errorf("%w: conflicting CPython collector branch target", errUnsupportedLayout)
			}
			branchStates[target] = *state
		}
		if unconditional {
			*state = threadStateCallMatchState{}
		}
		return 0, false, nil
	}
	// A return ends the current path; a saved forward-branch state can start a later path.
	//
	//	2b7f22: pop rbx
	//	2b7f23: pop r14
	//	2b7f25: pop rbp
	//	> 2b7f26: ret
	if strings.HasPrefix(inst.Op.String(), "RET") {
		*state = threadStateCallMatchState{}
		return 0, false, nil
	}
	if state.hasThread {
		// A write to the tracked register ends the proof that it still contains tstate.
		//
		//	268155: call __tls_get_addr@plt
		//	> 26815a: mov rbx,[rax+8]  // tracked tstate register
		//	...
		//	268178: mov rdi,rbx
		if destination, writes := writtenRegister(inst); writes && destination == state.thread {
			state.hasThread = false
			state.rdiReady, state.rsiReady, state.rdxReady = false, false, false
			return 0, false, nil
		}
		destination, argument := collectorArgumentRegister(inst.Args[0])
		if argument {
			switch destination {
			case x86asm.RDI:
				// Match the tracked tstate as the first gc_collect_main argument.
				//
				//	> 268178: mov rdi,rbx
				//	26817b: mov edx,2
				//	268184: mov esi,2
				source, register := inst.Args[1].(x86asm.Reg)
				state.rdiReady = inst.Op == x86asm.MOV && register && source == state.thread
			case x86asm.RSI, x86asm.RDX:
				// Match generation 2 in RSI or the manual-collection reason 2 in RDX.
				//
				//	268178: mov rdi,rbx
				//	> 26817b: mov edx,2
				//	> 268184: mov esi,2
				//	268189: call 1a39a0
				value, immediate := inst.Args[1].(x86asm.Imm)
				ready := inst.Op == x86asm.MOV && immediate && value == 2
				if destination == x86asm.RSI {
					state.rsiReady = ready
				} else {
					state.rdxReady = ready
				}
			}
		}
	}
	return 0, false, nil
}

func branchInstruction(inst x86asm.Inst) (branch, unconditional bool) {
	name := inst.Op.String()
	return strings.HasPrefix(name, "J") || strings.HasPrefix(name, "LOOP"), inst.Op == x86asm.JMP
}

// writtenRegister returns the explicit destination register for instructions used by the matcher.
func writtenRegister(inst x86asm.Inst) (x86asm.Reg, bool) {
	switch inst.Op {
	case x86asm.CMP, x86asm.TEST, x86asm.PUSH:
		return 0, false
	}
	return canonicalRegister(inst.Args[0])
}

func canonicalRegister(argument x86asm.Arg) (x86asm.Reg, bool) {
	register, found := argument.(x86asm.Reg)
	if !found {
		return 0, false
	}
	for _, group := range []struct{ first, last, base x86asm.Reg }{
		{x86asm.AL, x86asm.BL, x86asm.RAX},
		{x86asm.AH, x86asm.BH, x86asm.RAX},
		{x86asm.SPB, x86asm.R15B, x86asm.RSP},
		{x86asm.AX, x86asm.R15W, x86asm.RAX},
		{x86asm.EAX, x86asm.R15L, x86asm.RAX},
		{x86asm.RAX, x86asm.R15, x86asm.RAX},
	} {
		if register >= group.first && register <= group.last {
			return group.base + register - group.first, true
		}
	}
	return 0, false
}

func threadStateSurvivesCall(register x86asm.Reg) bool {
	return register == x86asm.RBX || register == x86asm.RBP ||
		register >= x86asm.R12 && register <= x86asm.R15
}

func collectorArgumentRegister(argument x86asm.Arg) (x86asm.Reg, bool) {
	register, found := argument.(x86asm.Reg)
	if !found {
		return 0, false
	}
	switch register {
	case x86asm.RDI, x86asm.EDI:
		return x86asm.RDI, true
	case x86asm.RSI, x86asm.ESI:
		return x86asm.RSI, true
	case x86asm.RDX, x86asm.EDX:
		return x86asm.RDX, true
	default:
		return 0, false
	}
}

func privateCollectorSymbolAddress(file *elf.File) (uint64, error) {
	var tables [][]elf.Symbol
	for _, read := range []func() ([]elf.Symbol, error){file.Symbols, file.DynamicSymbols} {
		symbols, err := read()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return 0, err
		}
		tables = append(tables, symbols)
	}
	return selectPrivateCollectorSymbol(tables...)
}

// selectPrivateCollectorSymbol accepts one recognized address across both symbol tables and rejects ambiguity.
func selectPrivateCollectorSymbol(tables ...[]elf.Symbol) (uint64, error) {
	var target uint64
	for _, symbols := range tables {
		for _, symbol := range symbols {
			// Require a defined collector function with a concrete body. Compiler-generated
			// .cold fragments do not represent the normal collector completion path.
			if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || symbol.Section == elf.SHN_UNDEF ||
				symbol.Value == 0 || strings.Contains(symbol.Name, ".cold") ||
				!recognizedCollectorName(symbol.Name) {
				continue
			}
			if target != 0 && target != symbol.Value {
				return 0, fmt.Errorf("%w: ambiguous private CPython collector symbols", errUnsupportedLayout)
			}
			target = symbol.Value
		}
	}
	if target == 0 {
		return 0, fmt.Errorf("%w: no private CPython collector symbol", errUnsupportedLayout)
	}
	return target, nil
}

func recognizedCollectorName(name string) bool {
	for _, base := range []string{"collect_with_callback", "gc_collect_main", "_PyGC_Collect", "gc_collect_internal"} {
		if name == base || strings.HasPrefix(name, base+".") {
			return true
		}
	}
	return false
}

// strictELFFileOffset maps one virtual address to exactly one executable file-backed load segment.
func strictELFFileOffset(file *elf.File, address uint64) (uint64, error) {
	var offset uint64
	matches := 0
	for _, program := range file.Progs {
		// Probe offsets must belong to an executable, file-backed load segment.
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 ||
			address < program.Vaddr || address-program.Vaddr >= program.Filesz {
			continue
		}
		candidate := program.Off + address - program.Vaddr
		if candidate < program.Off || candidate == 0 {
			return 0, fmt.Errorf("%w: invalid CPython probe file offset", errUnsupportedLayout)
		}
		offset = candidate
		matches++
	}
	if matches != 1 {
		return 0, fmt.Errorf("%w: CPython probe address maps to %d file segments", errUnsupportedLayout, matches)
	}
	return offset, nil
}

// repeatedCallCollector scans each three-call window and returns the middle target
// when the first and third targets match. Different middle targets are ambiguous.
func repeatedCallCollector(calls []uint64) (uint64, bool, error) {
	var candidate uint64
	for index := 0; index+2 < len(calls); index++ {
		before, collector, after := calls[index], calls[index+1], calls[index+2]
		if before != after || before == collector {
			continue
		}
		if candidate != 0 && candidate != collector {
			return 0, false, fmt.Errorf("%w: ambiguous private CPython collector", errUnsupportedLayout)
		}
		candidate = collector
	}
	return candidate, candidate != 0, nil
}

// relativeInstructionTarget resolves the signed displacement encoded by relative control flow.
func relativeInstructionTarget(decoded decodedInstruction) (uint64, error) {
	relative, ok := decoded.inst.Args[0].(x86asm.Rel)
	if !ok {
		return 0, errIndirectCall
	}
	next, err := addRelative(decoded.address, int64(decoded.inst.Len))
	if err != nil {
		return 0, err
	}
	return addRelative(next, int64(relative))
}

// addRelative applies a signed displacement without allowing address wraparound.
func addRelative(base uint64, delta int64) (uint64, error) {
	if delta < 0 {
		amount := uint64(-delta)
		if amount > base {
			return 0, errUnsupportedLayout
		}
		return base - amount, nil
	}
	if uint64(delta) > math.MaxUint64-base {
		return 0, errUnsupportedLayout
	}
	return base + uint64(delta), nil
}

// decodePythonInstruction reads at most the x86 15-byte instruction limit without crossing
// the bounded function end, and requires the instruction to start in file-backed executable code.
func decodePythonInstruction(file *elf.File, address, end uint64) (decodedInstruction, error) {
	if address >= end {
		return decodedInstruction{}, fmt.Errorf("%w: invalid CPython instruction bounds", errUnsupportedLayout)
	}
	if _, err := strictELFFileOffset(file, address); err != nil {
		return decodedInstruction{}, err
	}
	remaining := end - address
	data, err := readVirtualBytes(file, address, min(uint64(15), remaining))
	if err != nil {
		return decodedInstruction{}, err
	}
	// ENDBR64 marks valid indirect-branch destinations when CET is enabled and has
	// no register effects relevant to the collector matcher.
	if len(data) >= len(endBranch64Encoding) &&
		bytes.Equal(data[:len(endBranch64Encoding)], endBranch64Encoding[:]) {
		return decodedInstruction{
			address: address,
			inst:    x86asm.Inst{Op: x86asm.NOP, Len: len(endBranch64Encoding)},
		}, nil
	}
	inst, err := x86asm.Decode(data, 64)
	if err != nil || inst.Len == 0 || uint64(inst.Len) > remaining {
		return decodedInstruction{}, fmt.Errorf("%w: invalid CPython instruction at %#x", errUnsupportedLayout, address)
	}
	return decodedInstruction{address: address, inst: inst}, nil
}

// walkInstructions decodes one bounded function without crossing into the next function.
func walkInstructions(
	file *elf.File,
	start, size uint64,
	visit func(decodedInstruction) error,
) error {
	if size == 0 || size > maximumPythonFunctionSize || start > math.MaxUint64-size {
		return fmt.Errorf("%w: invalid CPython function bounds", errUnsupportedLayout)
	}
	end := start + size
	for address := start; address < end; {
		decoded, err := decodePythonInstruction(file, address, end)
		if err != nil {
			return err
		}
		if err := visit(decoded); err != nil {
			return err
		}
		address += uint64(decoded.inst.Len)
	}
	return nil
}

// addressInPLT reports whether an address belongs to an executable PLT section.
// The collector matcher uses it to separate dynamic-linker trampolines from local CPython calls.
func addressInPLT(file *elf.File, address uint64) bool {
	for _, name := range []string{".plt", ".plt.sec", ".plt.got"} {
		section := file.Section(name)
		if section != nil && address >= section.Addr && address-section.Addr < section.Size {
			return true
		}
	}
	return false
}

// validateCollectorTarget confirms that the selected middle call reaches a local function
// start backed by executable ELF bytes, suitable for the collector return probe.
func validateCollectorTarget(file *elf.File, starts []uint64, target uint64) error {
	_, found := slices.BinarySearch(starts, target)
	if !found || addressInPLT(file, target) {
		return fmt.Errorf("%w: CPython collector is not a local function start", errUnsupportedLayout)
	}
	_, err := strictELFFileOffset(file, target)
	return err
}

// collectorFromRepeatedCallShape finds CPython's internal collect or gc_collect_main
// function in the call pattern visible in a CPython 3.9-3.12 stripped build:
//
//	2780af: call 278110  // callback
//	2780c6: call 1fbdd0  // gc_collect_main
//	2780e5: call 278110  // callback
//
// The repeated callback address identifies the collector between the two calls.
func collectorFromRepeatedCallShape(
	file *elf.File,
	starts []uint64,
	root, rootSize uint64,
) (uint64, error) {
	// Inspect PyGC_Collect first because some builds contain the repeated-call pattern directly.
	rootCalls, err := directCalls(file, root, rootSize)
	if err != nil {
		return 0, err
	}

	var collector uint64
	// Equal first and third call targets identify the middle call as the GC function.
	// Every matching function must identify the same middle address.
	consider := func(calls []uint64) error {
		candidate, found, err := repeatedCallCollector(calls)
		if err != nil || !found {
			return err
		}
		if collector != 0 && collector != candidate {
			return fmt.Errorf("%w: ambiguous private CPython collector", errUnsupportedLayout)
		}
		collector = candidate
		return nil
	}
	if err := consider(rootCalls); err != nil {
		return 0, err
	}

	// Some builds place the repeated-call pattern in a direct PyGC_Collect wrapper:
	//
	//	PyGC_Collect: call <wrapper>
	//	<wrapper>:    call 278110  // callback
	//	              call 1fbdd0  // gc_collect_main
	//	              call 278110  // callback
	//
	// Inspect each local wrapper once, matching the single call level seen in CPython.
	for _, callee := range slices.Compact(slices.Sorted(slices.Values(rootCalls))) {
		// The .eh_frame_hdr function-start table confirms this target is a bounded local function.
		if _, found := slices.BinarySearch(starts, callee); !found {
			continue
		}
		size, err := boundedFunctionSize(starts, callee)
		if err != nil {
			continue
		}
		calls, err := directCalls(file, callee, size)
		// CPython 3.10 and 3.11 also call _PyErr_Restore, whose body contains
		// indirect deallocation calls. Continue with the other local callees.
		if errors.Is(err, errIndirectCall) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if err := consider(calls); err != nil {
			return 0, err
		}
	}

	if collector == 0 {
		return 0, fmt.Errorf("%w: private CPython collector not found", errUnsupportedLayout)
	}
	if err := validateCollectorTarget(file, starts, collector); err != nil {
		return 0, err
	}
	return collector, nil
}

// directCalls returns the ordered targets of GDB-style `call <address>` instructions.
// Calls into the Procedure Linkage Table resolve external functions and are excluded.
// An indirect call returns errIndirectCall because its target cannot join the ordered list.
func directCalls(file *elf.File, start, size uint64) ([]uint64, error) {
	var calls []uint64
	err := walkInstructions(file, start, size, func(decoded decodedInstruction) error {
		if decoded.inst.Op != x86asm.CALL {
			return nil
		}
		target, err := relativeInstructionTarget(decoded)
		if err != nil {
			return err
		}
		if !addressInPLT(file, target) {
			calls = append(calls, target)
		}
		return nil
	})
	return calls, err
}
