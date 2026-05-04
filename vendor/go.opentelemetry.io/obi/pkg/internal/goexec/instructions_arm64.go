// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"golang.org/x/arch/arm64/arm64asm"
)

const (
	armInstructionSize = 4
)

func FindReturnOffsets(baseOffset uint64, data []byte) ([]uint64, error) {
	var returnOffsets []uint64
	index := 0
	for index < len(data) {
		instruction, err := arm64asm.Decode(data[index:])
		if err == nil && instruction.Op == arm64asm.RET {
			returnOffsets = append(returnOffsets, baseOffset+uint64(index))
		}

		// arm64 instructions are fixed 4 bytes; advance unconditionally even on
		// decode errors so that truncated or unrecognized words are skipped cleanly.
		index += armInstructionSize
	}

	return returnOffsets, nil
}
