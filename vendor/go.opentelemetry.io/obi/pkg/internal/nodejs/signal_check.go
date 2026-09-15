// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	// sigusr1 is the signal the gates guard and sendSIGUSR1 sends: one
	// definition, so the mask bit cannot drift from the signal itself.
	sigusr1 = int(unix.SIGUSR1)
	// Offset of the signum field within the uv_signal_s struct (libuv 1.x, 64-bit).
	// This offset is stable across all libuv 1.x versions (used by Node.js 4.x through 22.x+).
	// Layout: UV_HANDLE_FIELDS (0x60) + uv_signal_cb (0x08) = 0x68.
	uvSignalSigNumOffset = 0x68
	// Offsets of the RB-tree left/right child pointers within uv_signal_s.
	// These are part of UV_SIGNAL_PRIVATE_FIELDS.tree_entry, which follows signum.
	uvSignalTreeLeftOffset  = 0x70
	uvSignalTreeRightOffset = 0x78
	// Maximum number of tree nodes to visit to prevent runaway reads.
	maxTreeNodes = 64
	// Maximum valid signal number (Linux).
	maxSignalNum = 64
)

const (
	signalTreeSymbol = "uv__signal_tree"
	sigusr1Mask      = uint64(1) << (sigusr1 - 1)
)

// nodeSymbols is what one walk of the executable's symbol tables yields.
// debug/elf caches nothing, so asking twice reparses the whole table, around
// twelve thousand symbols for a stock node.
type nodeSymbols struct {
	// signalTree is libuv's signal-handle tree root, when the table names it.
	signalTree procs.Sym
	hasTree    bool
}

// readNodeSymbols looks up libuv's signal tree. The lookup admits STT_FUNC as
// well as STT_OBJECT: uv__signal_tree is a data object, so this only widens the
// match to a function of that exact name, which no Node build has.
func readNodeSymbols(elfFile *elf.File) nodeSymbols {
	if elfFile == nil {
		return nodeSymbols{}
	}

	exact, err := procs.FindExeSymbols(elfFile,
		[]string{signalTreeSymbol}, elf.STT_FUNC, elf.STT_OBJECT)
	if err != nil {
		return nodeSymbols{}
	}

	tree, hasTree := exact[signalTreeSymbol]
	return nodeSymbols{signalTree: tree, hasTree: hasTree}
}

// hasUserSIGUSR1Handler checks whether a Node.js process has a JavaScript-level
// SIGUSR1 handler registered (via process.on('SIGUSR1', ...)).
//
// It does this by reading libuv's internal uv__signal_tree (an RB-tree of active
// signal handles) from the process's memory. If any node in the tree has signum == 10,
// the process has a custom SIGUSR1 handler and it is NOT safe to send SIGUSR1.
//
// Returns signalCheckFound if a handler is detected, signalCheckNotFound if no handler,
// or signalCheckFailed if the detection could not be performed (e.g. stripped symbols).
func hasUserSIGUSR1Handler(pid int, elfFile *elf.File, syms nodeSymbols) signalCheckResult {
	if elfFile == nil || elfFile.Class != elf.ELFCLASS64 {
		return signalCheckFailed
	}

	runtimeAddr, ok := signalTreeRuntimeAddr(pid, elfFile, syms)
	if !ok {
		return signalCheckFailed
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	mem, err := os.Open(memPath)
	if err != nil {
		return signalCheckFailed
	}
	defer mem.Close()

	rootPtr, err := readPtr(mem, int64(runtimeAddr), elfFile.ByteOrder)
	if err != nil {
		return signalCheckFailed
	}
	if rootPtr == 0 {
		return signalCheckNotFound
	}

	if walkTreeForSignal(mem, rootPtr, sigusr1, elfFile.ByteOrder) {
		return signalCheckFound
	}
	return signalCheckNotFound
}

func signalTreeRuntimeAddr(pid int, elfFile *elf.File, syms nodeSymbols) (uint64, bool) {
	if !syms.hasTree {
		return 0, false
	}
	sym := syms.signalTree

	// For PIE executables (ET_DYN), the symbol's virtual address is relative to the
	// load base. We need to find the actual runtime address by reading the executable's
	// base address from /proc/<pid>/maps.
	if elfFile.Type != elf.ET_DYN {
		return sym.Off, true
	}

	base, err := procs.FindExeBaseAddr(app.PID(pid))
	if err != nil {
		return 0, false
	}

	return base + sym.Off, true
}

func sigusr1Disposition(pid int) signalDisposition {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return signalDispositionUnknown
	}

	caught, gotCaught := signalMask(status, "SigCgt:")
	ignored, gotIgnored := signalMask(status, "SigIgn:")
	if !gotCaught || !gotIgnored {
		return signalDispositionUnknown
	}

	if (caught|ignored)&sigusr1Mask != 0 {
		return signalDispositionHandled
	}

	return signalDispositionFatal
}

func signalMask(status []byte, field string) (uint64, bool) {
	for line := range strings.SplitSeq(string(status), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), field)
		if !ok {
			continue
		}

		mask, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return 0, false
		}

		return mask, true
	}

	return 0, false
}

// walkTreeForSignal performs an iterative traversal of the libuv signal RB-tree
// looking for a node with the given signal number.
func walkTreeForSignal(mem *os.File, rootPtr uint64, signum int, byteOrder binary.ByteOrder) bool {
	stack := []uint64{rootPtr}
	visited := make(map[uint64]struct{}, maxTreeNodes)

	for len(stack) > 0 && len(visited) < maxTreeNodes {
		nodeAddr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if nodeAddr == 0 {
			continue
		}
		if _, seen := visited[nodeAddr]; seen {
			continue
		}
		visited[nodeAddr] = struct{}{}

		nodeSigNum, err := readInt32(mem, int64(nodeAddr)+uvSignalSigNumOffset, byteOrder)
		if err != nil {
			return false
		}

		// Sanity check: signal numbers should be in [1, 64]
		if nodeSigNum < 1 || nodeSigNum > maxSignalNum {
			return false
		}

		if nodeSigNum == int32(signum) {
			return true
		}

		left, err := readPtr(mem, int64(nodeAddr)+uvSignalTreeLeftOffset, byteOrder)
		if err != nil {
			return false
		}
		right, err := readPtr(mem, int64(nodeAddr)+uvSignalTreeRightOffset, byteOrder)
		if err != nil {
			return false
		}

		if left != 0 {
			stack = append(stack, left)
		}
		if right != 0 {
			stack = append(stack, right)
		}
	}

	return false
}

func readPtr(f *os.File, offset int64, byteOrder binary.ByteOrder) (uint64, error) {
	var buf [8]byte
	_, err := f.ReadAt(buf[:], offset)
	if err != nil {
		return 0, err
	}
	return byteOrder.Uint64(buf[:]), nil
}

func readInt32(f *os.File, offset int64, byteOrder binary.ByteOrder) (int32, error) {
	var buf [4]byte
	_, err := f.ReadAt(buf[:], offset)
	if err != nil {
		return 0, err
	}
	return int32(byteOrder.Uint32(buf[:])), nil
}

// sendSIGUSR1 signals through the pinned process handle, so the signal cannot
// reach a program the kernel gave the same PID after discovery saw the target.
// A variable so a test can assert that the gates decide whether this runs at
// all, which is the whole point of the refusals above it.
var sendSIGUSR1 = func(process *procs.ProcessHandle) error {
	return process.SendSignal(unix.SIGUSR1)
}
