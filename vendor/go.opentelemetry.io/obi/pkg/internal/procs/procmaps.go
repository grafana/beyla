// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func FindLibMaps(pid app.PID) ([]*procfs.ProcMap, error) {
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return nil, err
	}

	return proc.ProcMaps()
}

func LibPath(name string, maps []*procfs.ProcMap) *procfs.ProcMap {
	for _, m := range maps {
		if strings.Contains(m.Pathname, string(filepath.Separator)+name) && m.Perms.Execute {
			return m
		}
	}

	return nil
}

// FindExeBaseAddr returns the runtime load address of /proc/<pid>/exe.
// ELF object symbols in PIE/ET_DYN binaries are relative to this address; BPF
// needs the absolute process address to read globals from user memory.
func FindExeBaseAddr(pid app.PID) (uint64, error) {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return 0, fmt.Errorf("readlink exe: %w", err)
	}

	maps, err := FindLibMaps(pid)
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

// FindExeLoadBias returns the ELF load bias for /proc/<pid>/exe.
//
// Add this value to an ELF symbol virtual address to get the symbol's address
// in the running process. PIE binaries usually have a non-zero load bias;
// ET_EXEC binaries usually have a zero load bias.
func FindExeLoadBias(pid app.PID) (uint64, error) {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return 0, fmt.Errorf("readlink exe: %w", err)
	}

	exeFile, err := elf.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return 0, fmt.Errorf("open exe ELF: %w", err)
	}
	defer exeFile.Close()

	maps, err := FindLibMaps(pid)
	if err != nil {
		return 0, fmt.Errorf("read proc maps: %w", err)
	}

	return exeLoadBias(exePath, maps, exeFile.Progs)
}

func exeLoadBias(exePath string, maps []*procfs.ProcMap, progs []*elf.Prog) (uint64, error) {
	for _, m := range maps {
		if m.Pathname != exePath {
			continue
		}

		for _, prog := range progs {
			if prog.Type != elf.PT_LOAD || pageStart(prog.Off) != uint64(m.Offset) {
				continue
			}

			vaddr := pageStart(prog.Vaddr)
			if uint64(m.StartAddr) < vaddr {
				return 0, fmt.Errorf("invalid executable mapping address for %s", exePath)
			}
			return uint64(m.StartAddr) - vaddr, nil
		}
	}

	return 0, fmt.Errorf("executable mapping not found for %s", exePath)
}

func pageStart(addr uint64) uint64 {
	pageSize := uint64(os.Getpagesize())
	return addr & ^(pageSize - 1)
}
