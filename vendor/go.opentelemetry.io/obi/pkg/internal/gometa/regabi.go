// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gometa // import "go.opentelemetry.io/obi/pkg/internal/gometa"

// Arch selects a Go regabi layout.
type Arch uint8

const (
	ArchInvalid Arch = iota
	ArchAMD64
	ArchARM64
)

func (a Arch) String() string {
	switch a {
	case ArchAMD64:
		return "amd64"
	case ArchARM64:
		return "arm64"
	default:
		return "invalid"
	}
}

// pt_regs offsets in Go regabi arg order: AX, BX, CX, DI, SI, R8..R11.
var amd64IntRegs = []int{80, 40, 88, 112, 104, 72, 64, 56, 48}

// pt_regs offsets in Go regabi arg order: X0..X15.
var arm64IntRegs = []int{0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120}

// regList returns int-reg pt_regs offsets for arch.
func regList(a Arch) []int {
	switch a {
	case ArchAMD64:
		return amd64IntRegs
	case ArchARM64:
		return arm64IntRegs
	default:
		return nil
	}
}

// regAllocator hands out int-register slots in regabi order.
type regAllocator struct {
	regs []int
	idx  int
}

func newRegAllocator(arch Arch) *regAllocator {
	return &regAllocator{regs: regList(arch)}
}

// take consumes n consecutive slots.
func (a *regAllocator) take(n int) ([]int, bool) {
	if a.idx+n > len(a.regs) {
		return nil, false
	}
	out := a.regs[a.idx : a.idx+n]
	a.idx += n
	return out, true
}

// skip advances n slots for non-extractable kinds (slice, iface, ...).
func (a *regAllocator) skip(n int) {
	a.idx += n
	if a.idx > len(a.regs) {
		a.idx = len(a.regs)
	}
}
