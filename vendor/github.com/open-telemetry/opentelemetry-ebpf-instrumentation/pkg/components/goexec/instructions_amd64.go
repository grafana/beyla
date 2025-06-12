package goexec

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

func FindReturnOffsets(baseOffset uint64, data []byte) ([]uint64, error) {
	var returnOffsets []uint64
	index := 0
	for index < len(data) {
		// FIXME remove this once x86asm is able to recognize and decode
		// ENDBR64
		if isENDBRXX(data[index:]) {
			index += endbrSize
			continue
		}

		instruction, err := x86asm.Decode(data[index:], 64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode x64 instruction at offset %d: %w", index, err)
		}

		if instruction.Op == x86asm.RET {
			returnOffsets = append(returnOffsets, baseOffset+uint64(index))
		}

		index += instruction.Len
	}

	return returnOffsets, nil
}
