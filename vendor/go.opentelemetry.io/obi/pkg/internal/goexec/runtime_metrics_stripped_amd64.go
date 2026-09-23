// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"

	"golang.org/x/arch/x86/x86asm"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type runtimeMetricX86Instruction struct {
	offsetInFunction int
	inst             x86asm.Inst
}

// resolveGOMAXPROCSFromCode follows procresize's processor-count validation from
// machine code to the global's ELF address. Each matching RIP-relative load must
// point to aligned, writable int32 storage, and all matches must agree.
func resolveGOMAXPROCSFromCode(f *elf.File, functionELFAddress uint64, code []byte) (uint64, error) {
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	if err != nil {
		return 0, err
	}

	// Find the load used by procresize's check of the previous processor count.
	const gomaxprocsSize = 4 // The runtime declares gomaxprocs as int32.
	var candidates []uint64
	for index, instruction := range instructions {
		if !isGOMAXPROCSLoadSequence(instructions, index) {
			continue
		}
		globalELFAddress, ok := runtimeMetricRIPTarget(functionELFAddress, instruction)
		if !ok || globalELFAddress == 0 || globalELFAddress%gomaxprocsSize != 0 {
			continue
		}
		// A plausible instruction match must also point to four bytes of writable
		// global storage. This checks the address, not the variable's current value.
		if !runtimeMetricWritableRange(f, globalELFAddress, gomaxprocsSize) {
			continue
		}
		candidates = append(candidates, globalELFAddress)
	}
	return uniqueRuntimeMetricAddress(candidates)
}

// resolveRuntimeMetricSchedGoIDFromCode recovers the address of sched.goidgen
// from its eight-byte atomic update in oneNewExtraM. All valid matches must agree.
func resolveRuntimeMetricSchedGoIDFromCode(f *elf.File, functionELFAddress uint64, code []byte) (uint64, error) {
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	if err != nil {
		return 0, err
	}

	const goIDSize = 8
	var candidates []uint64
	for index, instruction := range instructions {
		if !isRuntimeMetricSchedGoIDUpdate(instructions, index) {
			continue
		}
		address, ok := runtimeMetricRIPTarget(functionELFAddress, instruction)
		if !ok || address == 0 || address%goIDSize != 0 {
			continue
		}
		if !runtimeMetricWritableRange(f, address, goIDSize) {
			continue
		}
		candidates = append(candidates, address)
	}
	return uniqueRuntimeMetricAddress(candidates)
}

// resolveRuntimeMetricAllgLenFromCode recovers allglen from the atomic length
// store in allgadd. All valid matches must identify the same writable uintptr.
func resolveRuntimeMetricAllgLenFromCode(f *elf.File, functionELFAddress uint64, code []byte) (uint64, error) {
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	if err != nil {
		return 0, err
	}

	const allgLenSize = 8 // uintptr is eight bytes on amd64.
	var candidates []uint64
	for index := range instructions {
		if !isRuntimeMetricAllgLenStore(instructions, index) {
			continue
		}
		// The LEA identifies the destination; the preceding MOV reads the length.
		address, ok := runtimeMetricRIPTarget(functionELFAddress, instructions[index+1])
		if !ok || address == 0 || address%allgLenSize != 0 {
			continue
		}
		if !runtimeMetricWritableRange(f, address, allgLenSize) {
			continue
		}
		candidates = append(candidates, address)
	}
	return uniqueRuntimeMetricAddress(candidates)
}

// resolveRuntimeMetricAllpFromCode recovers the global slice header, not the
// backing array whose pointer it contains. It first identifies pointer/length
// use in preemptall's loop, then checks their field addresses and storage.
func resolveRuntimeMetricAllpFromCode(f *elf.File, functionELFAddress uint64, code []byte) (uint64, error) {
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	if err != nil {
		return 0, err
	}

	const pointerSize = 8
	const sliceHeaderSize = 3 * pointerSize // Pointer, length, capacity on amd64.
	var candidates []uint64
	for index := range instructions {
		if !isRuntimeMetricAllpLoop(instructions, index) {
			continue
		}

		// The two global reads must refer to adjacent pointer and length fields.
		address, pointerOK := runtimeMetricRIPTarget(functionELFAddress, instructions[index])
		lengthAddress, lengthOK := runtimeMetricRIPTarget(functionELFAddress, instructions[index+2])
		if !pointerOK || !lengthOK || address == 0 || address%pointerSize != 0 ||
			address > ^uint64(0)-pointerSize || lengthAddress != address+pointerSize {
			continue
		}
		// The whole header must fit readable and writable storage, including BSS.
		if !runtimeMetricWritableRange(f, address, sliceHeaderSize) {
			continue
		}
		candidates = append(candidates, address)
	}
	return uniqueRuntimeMetricAddress(candidates)
}

// resolveRuntimeMetricSizeClassTableFromCode follows allocation-size lookups in
// mallocgc on older runtimes and in lockVerifyMSize on newer runtimes.
func resolveRuntimeMetricSizeClassTableFromCode(f *elf.File, table *gosym.Table) (uint64, error) {
	var candidates []uint64
	for _, name := range []string{"runtime.mallocgc", "runtime.lockVerifyMSize"} {
		function := table.LookupFunc(name)
		if function == nil {
			continue
		}
		if function.End <= function.Entry || function.End-function.Entry > maximumRuntimeFunctionSize {
			return 0, fmt.Errorf("invalid %s function bounds", name)
		}
		code, err := readVirtualMemoryWithFlags(f, function.Entry, function.End-function.Entry, elf.PF_X)
		if err != nil {
			return 0, err
		}
		addresses, err := runtimeMetricSizeClassTableCandidates(function.Entry, code)
		if err != nil {
			return 0, err
		}
		for _, address := range addresses {
			if runtimeMetricValidSizeClassTable(f, address) {
				candidates = append(candidates, address)
			}
		}
	}
	return uniqueRuntimeMetricAddress(candidates)
}

// runtimeMetricValidSizeClassTable checks the initialized allocation-size table.
// Go 1.17-1.27 tables contain 68 uint16 entries, matching the collector's limit.
func runtimeMetricValidSizeClassTable(f *elf.File, address uint64) bool {
	const (
		sizeClassCount = 68
		entrySize      = 2
		minimumSize    = 8
		maximumSize    = 32768
	)
	if f.ByteOrder == nil || address == 0 || address%entrySize != 0 {
		return false
	}
	data, err := readVirtualMemoryWithFlags(f, address, sizeClassCount*entrySize, elf.PF_R)
	if err != nil {
		return false
	}

	previous := uint16(0)
	for index := range sizeClassCount {
		size := f.ByteOrder.Uint16(data[index*entrySize:])
		if index == 0 {
			if size != 0 {
				return false
			}
			continue
		}
		if size <= previous || size%minimumSize != 0 || index == 1 && size != minimumSize {
			return false
		}
		previous = size
	}
	return previous == maximumSize
}

// runtimeMetricSizeClassTableCandidates finds table addresses referenced by one
// allocator anchor. The caller validates the table and resolves ambiguity across anchors.
func runtimeMetricSizeClassTableCandidates(functionELFAddress uint64, code []byte) ([]uint64, error) {
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	if err != nil {
		return nil, err
	}

	var candidates []uint64
	for index, instruction := range instructions {
		if !isRuntimeMetricSizeClassTableLoad(instructions, index) {
			continue
		}
		address, ok := runtimeMetricRIPTarget(functionELFAddress, instruction)
		if !ok || address == 0 {
			continue
		}
		candidates = append(candidates, address)
	}
	return candidates, nil
}

// resolveRuntimeMetricReceiverFromCode finds the address passed to a method.
// For memstats.heapStats.acquire(), the LEA supplies &memstats.heapStats;
// subtracting the field offset to recover memstats is the caller's responsibility.
func resolveRuntimeMetricReceiverFromCode(functionELFAddress uint64, code []byte, methodELFAddresses ...uint64) (uint64, error) {
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	if err != nil {
		return 0, err
	}
	var candidates []uint64
	for index, instruction := range instructions {
		for _, methodELFAddress := range methodELFAddresses {
			if !isRuntimeMetricReceiverCall(instructions, index, functionELFAddress, methodELFAddress) {
				continue
			}
			address, ok := runtimeMetricRIPTarget(functionELFAddress, instruction)
			if !ok || address == 0 {
				continue
			}
			candidates = append(candidates, address)
			break
		}
	}
	return uniqueRuntimeMetricAddress(candidates)
}

// uniqueRuntimeMetricAddress accepts repeated references to one address, but
// rejects distinct candidates because instruction matching cannot choose between them.
func uniqueRuntimeMetricAddress(candidates []uint64) (uint64, error) {
	if len(candidates) == 0 {
		return 0, errors.New("runtime global address not found")
	}
	address := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate != address {
			return 0, errors.New("ambiguous runtime global address")
		}
	}
	return address, nil
}

// decodeRuntimeMetricX86Instructions turns file bytes into instructions.
func decodeRuntimeMetricX86Instructions(code []byte) ([]runtimeMetricX86Instruction, error) {
	var instructions []runtimeMetricX86Instruction
	err := walkX86Instructions(code, func(offset int, inst x86asm.Inst) {
		instructions = append(instructions, runtimeMetricX86Instruction{offsetInFunction: offset, inst: inst})
	})
	if err != nil {
		return nil, err
	}
	for _, instruction := range instructions {
		// x86asm can report an incomplete instruction as Op == 0 without an error.
		if instruction.inst.Op == 0 {
			return nil, fmt.Errorf("invalid runtime instruction at offset %d", instruction.offsetInFunction)
		}
	}
	return instructions, nil
}

// isGOMAXPROCSLoadSequence recognizes procresize's check of the previous processor
// count. Before resizing the Go scheduler, procresize reads old := gomaxprocs and
// rejects old < 0. On amd64, that check has this shape:
// Source: https://go.dev/src/runtime/proc.go (runtime.procresize).
//
//	MOV  EDX, [RIP+displacement]  // read the int32 gomaxprocs global
//	TEST EDX, EDX                // set condition flags from the old count
//	JL   invalidArg              // branch if the old count is negative
func isGOMAXPROCSLoadSequence(instructions []runtimeMetricX86Instruction, index int) bool {
	if index < 0 || index > len(instructions)-3 {
		return false
	}

	// Require a 32-bit read from a global addressed relative to this instruction.
	load := instructions[index].inst
	register, registerOK := load.Args[0].(x86asm.Reg)
	memory, memoryOK := load.Args[1].(x86asm.Mem)
	if load.Op != x86asm.MOV || load.MemBytes != 4 || !registerOK || !memoryOK || memory.Base != x86asm.RIP {
		return false
	}

	test := instructions[index+1].inst
	branch := instructions[index+2].inst
	return test.Op == x86asm.TEST &&
		test.Args[0] == register && test.Args[1] == register &&
		branch.Op == x86asm.JL
}

// isRuntimeMetricSizeClassTableLoad recognizes a size-class table address
// followed by a uint16 lookup indexed by the size class.
// In runtime.lockVerifyMSize, the inlined roundupsize lookup has this form:
//
//	gc.SizeClassToSize[classIndex]
//
//	LEA   RCX, [RIP + displacement] // Calculate the table's base address.
//	MOVZX EAX, WORD PTR [RCX+RAX*2] // Read the uint16 entry indexed by RAX.
//
// Register choices may vary; the lookup must use the LEA destination as its base.
func isRuntimeMetricSizeClassTableLoad(instructions []runtimeMetricX86Instruction, index int) bool {
	if index < 0 || index > len(instructions)-2 {
		return false
	}

	address := instructions[index].inst
	base, baseOK := address.Args[0].(x86asm.Reg)
	source, sourceOK := address.Args[1].(x86asm.Mem)
	if address.Op != x86asm.LEA || !baseOK || base < x86asm.RAX || base > x86asm.R15 ||
		!sourceOK || source.Base != x86asm.RIP || source.Index != 0 {
		return false
	}

	load := instructions[index+1].inst
	memory, memoryOK := load.Args[1].(x86asm.Mem)
	return load.Op == x86asm.MOVZX && load.MemBytes == 2 && memoryOK &&
		memory.Base == base &&
		memory.Index >= x86asm.RAX && memory.Index <= x86asm.R15 &&
		memory.Scale == 2 && memory.Disp == 0
}

// isRuntimeMetricSchedGoIDUpdate recognizes the eight-byte atomic update in
// runtime.oneNewExtraM:
//
//	gp.goid = sched.goidgen.Add(1)
//
//	LEA  RDX, [RIP + displacement] // Address of sched.goidgen.
//	LOCK XADD QWORD PTR [RDX], RCX // Atomically update the eight-byte field.
//
// The same function updates the four-byte sched.ngsys field; width distinguishes it.
func isRuntimeMetricSchedGoIDUpdate(instructions []runtimeMetricX86Instruction, index int) bool {
	if index < 0 || index > len(instructions)-2 {
		return false
	}

	address := instructions[index].inst
	base, baseOK := address.Args[0].(x86asm.Reg)
	source, sourceOK := address.Args[1].(x86asm.Mem)
	if address.Op != x86asm.LEA || !baseOK || base < x86asm.RAX || base > x86asm.R15 ||
		!sourceOK || source.Base != x86asm.RIP || source.Index != 0 {
		return false
	}

	update := instructions[index+1].inst
	memory, memoryOK := update.Args[0].(x86asm.Mem)
	if update.Op != x86asm.XADD || update.MemBytes != 8 || !memoryOK ||
		memory.Base != base || memory.Index != 0 || memory.Disp != 0 || memory.Segment != 0 {
		return false
	}
	for _, prefix := range update.Prefix {
		if prefix == x86asm.PrefixLOCK {
			return true
		}
	}
	return false
}

// isRuntimeMetricAllgLenStore recognizes this atomic store in runtime.allgadd:
//
//	atomic.Storeuintptr(&allglen, uintptr(len(allgs)))
//
//	MOV  RCX, QWORD PTR [RIP + displacement] // Load len(allgs).
//	LEA  RDX, [RIP + displacement]           // Address of allglen.
//	XCHG QWORD PTR [RDX], RCX                // Atomically store the length.
//
// The nearby allgptr exchange lacks this adjacent global load of its source value.
func isRuntimeMetricAllgLenStore(instructions []runtimeMetricX86Instruction, index int) bool {
	if index < 0 || index > len(instructions)-3 {
		return false
	}

	load := instructions[index].inst
	value, valueOK := load.Args[0].(x86asm.Reg)
	source, sourceOK := load.Args[1].(x86asm.Mem)
	if load.Op != x86asm.MOV || load.MemBytes != 8 ||
		!valueOK || value < x86asm.RAX || value > x86asm.R15 ||
		!sourceOK || source.Base != x86asm.RIP || source.Index != 0 || source.Segment != 0 {
		return false
	}

	address := instructions[index+1].inst
	base, baseOK := address.Args[0].(x86asm.Reg)
	target, targetOK := address.Args[1].(x86asm.Mem)
	if address.Op != x86asm.LEA || !baseOK || base < x86asm.RAX || base > x86asm.R15 || base == value ||
		!targetOK || target.Base != x86asm.RIP || target.Index != 0 || target.Segment != 0 {
		return false
	}

	store := instructions[index+2].inst
	memory, memoryOK := store.Args[0].(x86asm.Mem)
	return store.Op == x86asm.XCHG && store.MemBytes == 8 && store.Args[1] == value &&
		memoryOK && memory.Base == base && memory.Index == 0 && memory.Disp == 0 && memory.Segment == 0
}

// runtimeMetricAllpLoadRegisters reads the candidate pointer and length registers
// from three instructions: a global load, a stack save, and a second global load.
// It proves that the loads are eight-byte RIP-relative reads into distinct
// registers. The caller must check their global addresses and subsequent loop use.
func runtimeMetricAllpLoadRegisters(instructions []runtimeMetricX86Instruction, index int) (pointer, length x86asm.Reg, ok bool) {
	if index < 0 || index > len(instructions)-3 {
		return 0, 0, false
	}
	var registers [2]x86asm.Reg
	for field, offset := range []int{0, 2} {
		load := instructions[index+offset].inst
		register, registerOK := load.Args[0].(x86asm.Reg)
		source, sourceOK := load.Args[1].(x86asm.Mem)
		if load.Op != x86asm.MOV || load.MemBytes != 8 ||
			!registerOK || register < x86asm.RAX || register > x86asm.R15 || register == x86asm.RSP ||
			!sourceOK || source.Base != x86asm.RIP || source.Index != 0 || source.Segment != 0 {
			return 0, 0, false
		}
		registers[field] = register
	}
	pointer, length = registers[0], registers[1]
	if pointer == length {
		return 0, 0, false
	}
	// The middle instruction saves the pointer without changing its register.
	save := instructions[index+1].inst
	stack, stackOK := save.Args[0].(x86asm.Mem)
	if save.Op != x86asm.MOV || save.MemBytes != 8 || save.Args[1] != pointer ||
		!stackOK || stack.Base != x86asm.RSP || stack.Index != 0 || stack.Segment != 0 {
		return 0, 0, false
	}
	return pointer, length, true
}

// isRuntimeMetricAllpLoopAccess checks how the candidate pointer and length are
// used at a loop boundary. The comparison must use length, and the element read
// must use pointer with the same index and an eight-byte stride:
//
//	CMP RSI, RDX                  // Index against length.
//	JGE loopExit                  // Skip the read when the index reaches length.
//	MOV RAX, QWORD PTR [RCX+RSI*8] // Read one P pointer.
//
// The caller must establish that pointer and length still hold the global loads.
func isRuntimeMetricAllpLoopAccess(instructions []runtimeMetricX86Instruction, index int, pointer, length x86asm.Reg) bool {
	if index < 0 || index > len(instructions)-3 {
		return false
	}
	compare := instructions[index].inst
	iterator, ok := compare.Args[0].(x86asm.Reg)
	if compare.Op != x86asm.CMP || compare.Args[1] != length ||
		!ok || iterator < x86asm.RAX || iterator > x86asm.R15 ||
		iterator == x86asm.RSP || iterator == pointer || iterator == length {
		return false
	}

	branch, load := instructions[index+1].inst, instructions[index+2].inst
	exit, exitOK := branch.Args[0].(x86asm.Rel)
	element, elementOK := load.Args[0].(x86asm.Reg)
	memory, memoryOK := load.Args[1].(x86asm.Mem)
	return branch.Op == x86asm.JGE && exitOK && int64(exit) >= int64(load.Len) &&
		load.Op == x86asm.MOV && load.MemBytes == 8 &&
		elementOK && element >= x86asm.RAX && element <= x86asm.R15 && element != x86asm.RSP &&
		memoryOK && memory.Base == pointer && memory.Index == iterator && memory.Scale == 8 &&
		memory.Disp == 0 && memory.Segment == 0
}

// isRuntimeMetricAllpLoop recognizes preemptall's "for _, pp := range allp":
//
//	MOV RCX, [RIP+disp]       // Backing-array pointer.
//	MOV [RSP+disp], RCX
//	MOV RDX, [RIP+disp]       // Slice length.
//	...                      // Preserve RCX and RDX.
//	CMP RSI, RDX
//	JGE loopExit
//	MOV RAX, [RCX+RSI*8]      // Read one P pointer.
//
// The caller validates that the two global addresses form a slice header.
func isRuntimeMetricAllpLoop(instructions []runtimeMetricX86Instruction, index int) bool {
	// First identify the values to follow; then verify how the loop uses them.
	pointer, length, ok := runtimeMetricAllpLoadRegisters(instructions, index)
	if !ok {
		return false
	}

	// Bound the search and allow only instructions that preserve both loads.
	// A forward jump must land on the comparison, not bypass the checked use.
	const maximumSetupInstructions = 12
	jumpTarget := int64(-1)
	for next := index + 3; next < len(instructions) && next < index+maximumSetupInstructions; next++ {
		instruction := instructions[next]
		inst := instruction.inst
		switch inst.Op {
		case x86asm.CMP:
			// Any setup jump must reach this check. The helper then verifies
			// that the comparison and element read use our preserved values.
			if jumpTarget != -1 && jumpTarget != int64(instruction.offsetInFunction) {
				return false
			}
			return isRuntimeMetricAllpLoopAccess(instructions, next, pointer, length)
		case x86asm.MOV:
			// Stack stores preserve registers; further loads or register copies
			// would require tracking a new value, so reject them here.
			memory, ok := inst.Args[0].(x86asm.Mem)
			if !ok || memory.Base != x86asm.RSP || memory.Index != 0 || memory.Segment != 0 {
				return false
			}
		case x86asm.XOR, x86asm.INC:
			// Loop setup may change other registers, but not our pointer or length.
			register, ok := inst.Args[0].(x86asm.Reg)
			if !ok || register < x86asm.EAX || register > x86asm.R15 {
				return false
			}
			// Normalize 32-bit writes, which also overwrite their 64-bit register.
			if register <= x86asm.R15L {
				register = register - x86asm.EAX + x86asm.RAX
			}
			if register == pointer || register == length || register == x86asm.RSP {
				return false
			}
		case x86asm.JMP:
			// The first iteration skips the increment and jumps to the comparison.
			// Record its target so the CMP case can verify where it lands.
			distance, ok := inst.Args[0].(x86asm.Rel)
			if !ok || distance <= 0 || jumpTarget != -1 {
				return false
			}
			jumpTarget = int64(instruction.offsetInFunction) + int64(inst.Len) + int64(distance)
		case x86asm.NOP:
		default:
			return false
		}
	}
	return false
}

// isRuntimeMetricReceiverCall recognizes method calls such as this in mcache.refill:
//
//	stats := memstats.heapStats.acquire()
//
//	LEA  RAX, [RIP + displacement] // Pass &memstats.heapStats as the receiver.
//	CALL acquire                  // Invoke consistentHeapStats.acquire.
//
// Go's amd64 register ABI passes the receiver in RAX.
func isRuntimeMetricReceiverCall(instructions []runtimeMetricX86Instruction, index int, functionELFAddress, methodELFAddress uint64) bool {
	if index < 0 || index >= len(instructions) {
		return false
	}
	load := instructions[index].inst
	memory, ok := load.Args[1].(x86asm.Mem)
	if load.Op != x86asm.LEA || load.Args[0] != x86asm.RAX || !ok || memory.Base != x86asm.RIP || memory.Index != 0 {
		return false
	}

	// Only padding may separate the receiver setup from the call.
	index++
	for index < len(instructions) && instructions[index].inst.Op == x86asm.NOP {
		index++
	}
	if index == len(instructions) {
		return false
	}
	target, ok := runtimeMetricCallTarget(functionELFAddress, instructions[index])
	return ok && target == methodELFAddress
}

// runtimeMetricCallTarget decodes the CALL part of a method call such as
// memstats.heapStats.acquire() in mcache.refill:
//
//	0x420486: e8 95 eb 01 00  CALL 0x43f020
//	          next instruction + stored displacement = destination
//	          0x42048b         + 0x1eb95             = 0x43f020
//
// Comparing the destination with acquire.Entry identifies the call to acquire.
func runtimeMetricCallTarget(functionELFAddress uint64, instruction runtimeMetricX86Instruction) (uint64, bool) {
	relative, ok := instruction.inst.Args[0].(x86asm.Rel)
	if instruction.inst.Op != x86asm.CALL || !ok || instruction.offsetInFunction < 0 || instruction.inst.Len <= 0 {
		return 0, false
	}
	instructionELFAddress, ok := procs.AddSignedOffset(functionELFAddress, int64(instruction.offsetInFunction))
	if !ok {
		return 0, false
	}
	// The displacement is relative to the address immediately after the CALL.
	nextInstructionELFAddress, ok := procs.AddSignedOffset(instructionELFAddress, int64(instruction.inst.Len))
	if !ok {
		return 0, false
	}
	return procs.AddSignedOffset(nextInstructionELFAddress, int64(relative))
}

// runtimeMetricRIPTarget calculates the ELF address read by a RIP-relative load:
// function address + instruction offset + instruction length + displacement.
func runtimeMetricRIPTarget(functionELFAddress uint64, instruction runtimeMetricX86Instruction) (uint64, bool) {
	memory, ok := instruction.inst.Args[1].(x86asm.Mem)
	if !ok || memory.Base != x86asm.RIP || instruction.offsetInFunction < 0 || instruction.inst.Len <= 0 {
		return 0, false
	}
	instructionELFAddress, ok := procs.AddSignedOffset(functionELFAddress, int64(instruction.offsetInFunction))
	if !ok {
		return 0, false
	}
	// RIP-relative operands use the address immediately after this instruction.
	nextInstructionELFAddress, ok := procs.AddSignedOffset(instructionELFAddress, int64(instruction.inst.Len))
	if !ok {
		return 0, false
	}
	// RIP-relative operands encode a signed 32-bit displacement. x86asm can
	// expose its raw bits as a positive int64, so sign-extend before adding it.
	return procs.AddSignedOffset(nextInstructionELFAddress, int64(int32(memory.Disp)))
}
