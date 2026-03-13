// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	sigusr1 = 10
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

// hasUserSIGUSR1Handler checks whether a Node.js process has a JavaScript-level
// SIGUSR1 handler registered (via process.on('SIGUSR1', ...)).
//
// It does this by reading libuv's internal uv__signal_tree (an RB-tree of active
// signal handles) from the process's memory. If any node in the tree has signum == 10,
// the process has a custom SIGUSR1 handler and it is NOT safe to send SIGUSR1.
//
// Returns true if a custom handler is detected, false if safe to proceed.
// Returns false on any error (fail-open: if we can't determine, attempt injection).
func hasUserSIGUSR1Handler(pid int, elfFile *elf.File) bool {
	if elfFile.Class != elf.ELFCLASS64 {
		return false
	}

	syms, err := procs.FindExeSymbols(elfFile, []string{"uv__signal_tree"}, elf.STT_OBJECT)
	if err != nil {
		return false
	}
	sym, ok := syms["uv__signal_tree"]
	if !ok {
		return false
	}
	symVAddr := sym.Off

	// For PIE executables (ET_DYN), the symbol's virtual address is relative to the
	// load base. We need to find the actual runtime address by reading the executable's
	// base address from /proc/<pid>/maps.
	runtimeAddr := symVAddr
	if elfFile.Type == elf.ET_DYN {
		base, err := findExeBaseAddr(pid)
		if err != nil {
			return false
		}
		runtimeAddr = base + symVAddr
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	mem, err := os.Open(memPath)
	if err != nil {
		return false
	}
	defer mem.Close()

	rootPtr, err := readPtr(mem, int64(runtimeAddr), elfFile.ByteOrder)
	if err != nil || rootPtr == 0 {
		return false
	}

	return walkTreeForSignal(mem, rootPtr, sigusr1, elfFile.ByteOrder)
}

// findExeBaseAddr reads /proc/<pid>/maps to find the base virtual address
// where the main executable is mapped. This is needed for PIE binaries where
// ELF symbol addresses are relative to the load base.
func findExeBaseAddr(pid int) (uint64, error) {
	exeLink := fmt.Sprintf("/proc/%d/exe", pid)
	exePath, err := os.Readlink(exeLink)
	if err != nil {
		return 0, fmt.Errorf("readlink exe: %w", err)
	}

	maps, err := procs.FindLibMaps(app.PID(pid))
	if err != nil {
		return 0, fmt.Errorf("read proc maps: %w", err)
	}

	for _, m := range maps {
		if m.Pathname == exePath {
			return uint64(m.StartAddr), nil
		}
	}

	return 0, fmt.Errorf("executable mapping not found in /proc/%d/maps", pid)
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
