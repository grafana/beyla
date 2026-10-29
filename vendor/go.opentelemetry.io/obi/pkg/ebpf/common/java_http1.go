// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// SupportsJavaHTTP1ReservationCleanup checks the ownership instruction once.
// Kernel backports make a version check unreliable.
var SupportsJavaHTTP1ReservationCleanup = sync.OnceValue(probeJavaHTTP1CompareAndSwap)

func probeJavaHTTP1CompareAndSwap() bool {
	// Load only: this program is never attached to a probe or run against traffic.
	// Successful verification establishes that the kernel accepts the instruction.
	probe, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "obi_http1_cas",
		Type:         ebpf.Kprobe,
		Instructions: javaHTTP1CompareAndSwapProbe(),
		License:      "Dual MIT/GPL",
	})
	if err != nil {
		slog.With("component", "java.HttpClient").Info("Java HttpClient header propagation disabled: atomic retirement unavailable", "error", err)
		return false
	}
	probe.Close()
	return true
}

// javaHTTP1CompareAndSwapProbe builds a tiny eBPF program with the same 64-bit
// atomic operation used by java_http1_request_retire in
// bpf/generictracer/maps/java_http1_requests.h. In that helper, changing the
// reservation's state from its request ID to an owned state claims removal.
// The comparison and write happen as one operation, so competing callers cannot
// both claim it.
//
// The equivalent C program is:
//
//	uint64_t state = 0;
//	(void)__sync_val_compare_and_swap(&state, 0, 1);
//	return 0;
//
// We only ask the kernel to load and verify this program; we never execute it.
// Its return value is therefore not the capability-test result. The Go caller
// returns true if the kernel accepts the program, or false if loading fails.
// The stack variable is private scratch space, so no application memory or
// reservation map is needed to check whether this instruction is accepted.
//
// Reading the instructions below:
//   - R0, R1 and R2 are registers (temporary value holders) in the eBPF virtual
//     machine, independent of the host CPU's register names. R0 also holds the
//     program's return value. CMPXCHG specifically requires its expected value
//     in R0 and overwrites R0 with the value previously stored in memory.
//   - RFP is R10, the read-only frame pointer marking the end of the eBPF stack.
//     The eight bytes just below it, R10-8 through R10-1, hold our uint64_t state.
//     R1 points to that slot; R2 holds the replacement value to write there.
//   - Imm means a literal number; Reg means copying another register's value.
//     DWord selects an eight-byte (64-bit) memory operation, matching the real
//     reservation state. Mem operates on memory at a register's address plus
//     the supplied byte offset.
//
// CMPXCHG's implicit R0 input/output and memory semantics are specified at:
// https://docs.kernel.org/bpf/standardization/instruction-set.html#atomic-operations
func javaHTTP1CompareAndSwapProbe() asm.Instructions {
	const (
		// eBPF stack slots are addressed backwards from the frame pointer.
		stateOffset  = -8 // one 64-bit reservation state
		stateAddress = asm.R1
		replacement  = asm.R2
		// CMPXCHG requires the expected value in R0, also the return register.
		expected = asm.R0
	)

	compareAndSwap := asm.CmpXchg.Mem(stateAddress, replacement, asm.DWord, 0)
	// cilium/ebpf v0.22 marshals the immediate before translating AtomicOp.
	// Supply it explicitly so the kernel sees CMPXCHG, rather than atomic ADD.
	compareAndSwap.Constant = int64(asm.CmpXchg >> 8)

	return asm.Instructions{
		// R0 = 0: supply the expected old state for the later comparison.
		// This zero also supplies the value used to initialize the stack slot.
		asm.Mov.Imm(expected, 0),

		// *(uint64_t *)(R10 - 8) = R0: initialize all eight bytes of state.
		// The verifier rejects reads of uninitialized stack memory. Use a
		// register store because this library disallows StoreImm with DWord.
		asm.StoreMem(asm.RFP, stateOffset, expected, asm.DWord),

		// R1 = R10: copy the stack boundary into a writable register.
		// We cannot adjust R10 itself because the frame pointer is read-only.
		asm.Mov.Reg(stateAddress, asm.RFP),

		// R1 -= 8: R1 now points to state, rather than the stack boundary.
		asm.Add.Imm(stateAddress, stateOffset),

		// R2 = 1: supply the new state to write if the comparison succeeds.
		asm.Mov.Imm(replacement, 1),

		// Atomically read the 64-bit value at R1 + 0 and compare it with R0.
		// If equal, store R2 there. Either way, put the old memory value in R0.
		// The final argument is a byte offset from R1, not the expected value.
		// If executed here, state would change from 0 to 1 and R0 would be 0.
		compareAndSwap,

		// R0 = 0: explicitly set the program's return value after CMPXCHG,
		// which uses the same register for its own result.
		asm.Mov.Imm(asm.R0, 0),

		// Exit the eBPF program, returning the value in R0 to the kernel.
		// Even a load-only probe must contain a valid program exit.
		asm.Return(),
	}
}

// SupportsJavaHTTP1Propagation is shared by Java attachment and the eBPF loader,
// so neither side enables header injection without the required kernel support.
func SupportsJavaHTTP1Propagation(log *slog.Logger) bool {
	return !IntegrityModeOverride && SupportsJavaHTTP1ReservationCleanup() && SupportsContextPropagationWithProbe(log)
}

// DisableJavaHTTP1Atomics removes unreachable reservation instructions on
// kernels without CMPXCHG. Both the generic and Go tracers include the shared
// HTTP parser. Older verifiers reject unknown encodings before eliminating
// branches behind a false g_bpf_java_http1_enabled constant.
func DisableJavaHTTP1Atomics(spec *ebpf.CollectionSpec) {
	for _, program := range spec.Programs {
		for n, instruction := range program.Instructions {
			if instruction.OpCode.AtomicOp() == asm.CmpXchg {
				// Keep one instruction so jump offsets remain valid. R0 is
				// CMPXCHG's result; -1 cannot be a readable request ID.
				program.Instructions[n] = asm.Mov.Imm(asm.R0, -1).WithMetadata(instruction.Metadata)
			}
		}
	}
}
