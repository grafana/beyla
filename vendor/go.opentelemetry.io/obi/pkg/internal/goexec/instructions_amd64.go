// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

const endbrSize = 4

func isENDBRXX(data []uint8) bool {
	if len(data) < endbrSize {
		return false
	}

	return data[0] == 0xF3 &&
		data[1] == 0x0F &&
		data[2] == 0x1E &&
		(data[3] == 0xFA || data[3] == 0xFB)
}

func walkX86Instructions(data []byte, visit func(int, x86asm.Inst)) error {
	for index := 0; index < len(data); {
		// FIXME remove this once x86asm is able to recognize and decode
		// ENDBR64
		if isENDBRXX(data[index:]) {
			index += endbrSize
			continue
		}

		instruction, err := x86asm.Decode(data[index:], 64)
		if err != nil {
			return fmt.Errorf("failed to decode x64 instruction at offset %d: %w", index, err)
		}

		visit(index, instruction)
		index += instruction.Len
	}

	return nil
}

func FindReturnOffsets(baseOffset uint64, data []byte) ([]uint64, error) {
	var returnOffsets []uint64
	err := walkX86Instructions(data, func(index int, instruction x86asm.Inst) {
		if instruction.Op == x86asm.RET {
			returnOffsets = append(returnOffsets, baseOffset+uint64(index))
		}
	})
	return returnOffsets, err
}

func FindCallTargets(baseOffset uint64, data []byte) ([]uint64, error) {
	var targets []uint64
	err := walkX86Instructions(data, func(index int, instruction x86asm.Inst) {
		if instruction.Op == x86asm.CALL {
			if relative, ok := instruction.Args[0].(x86asm.Rel); ok {
				target := int64(baseOffset) + int64(index+instruction.Len) + int64(relative)
				if target >= 0 {
					targets = append(targets, uint64(target))
				}
			}
		}
	})
	return targets, err
}

// FindPadStartOffset locates the compiler sequence that loads a PadLength byte
// from the stack and branches when the value is zero.
func FindPadStartOffset(baseOffset uint64, data []byte) (uint64, uint64, error) {
	type decoded struct {
		index int
		inst  x86asm.Inst
	}
	instructions := make([]decoded, 0, len(data)/4)
	err := walkX86Instructions(data, func(index int, instruction x86asm.Inst) {
		instructions = append(instructions, decoded{index: index, inst: instruction})
	})
	if err != nil {
		return 0, 0, err
	}

	for index := 0; index+2 < len(instructions); index++ {
		load := instructions[index].inst
		if load.Op != x86asm.MOVZX || load.MemBytes != 1 {
			continue
		}
		destination, dstOK := load.Args[0].(x86asm.Reg)
		memory, memOK := load.Args[1].(x86asm.Mem)
		if !dstOK || !memOK || memory.Base != x86asm.RSP || memory.Disp <= 0 || memory.Disp >= 512 {
			continue
		}

		next := index + 1
		for next < len(instructions) && instructions[next].inst.Op == x86asm.NOP {
			next++
		}
		if next+1 >= len(instructions) || instructions[next].inst.Op != x86asm.TEST {
			continue
		}
		testA, aOK := instructions[next].inst.Args[0].(x86asm.Reg)
		testB, bOK := instructions[next].inst.Args[1].(x86asm.Reg)
		if aOK && bOK && testA == testB && sameX86Register(testA, destination) &&
			instructions[next+1].inst.Op == x86asm.JE {
			return baseOffset + uint64(instructions[index].index), uint64(memory.Disp), nil
		}
	}

	return 0, 0, nil
}

func sameX86Register(left, right x86asm.Reg) bool {
	leftNumber, leftOK := x86RegisterNumber(left)
	rightNumber, rightOK := x86RegisterNumber(right)
	return leftOK && rightOK && leftNumber == rightNumber
}

func x86RegisterNumber(register x86asm.Reg) (int, bool) {
	switch {
	case register >= x86asm.AL && register <= x86asm.BL:
		return int(register - x86asm.AL), true
	case register >= x86asm.SPB && register <= x86asm.R15B:
		return int(register-x86asm.SPB) + 4, true
	case register >= x86asm.AX && register <= x86asm.R15W:
		return int(register - x86asm.AX), true
	case register >= x86asm.EAX && register <= x86asm.R15L:
		return int(register - x86asm.EAX), true
	case register >= x86asm.RAX && register <= x86asm.R15:
		return int(register - x86asm.RAX), true
	default:
		return 0, false
	}
}
