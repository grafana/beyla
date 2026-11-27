// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	"os"
	"sync"
	"syscall"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Distinct Rust executables whose analysis is kept. Replicas and forked workers
// of one binary share a single entry.
const rustExecutableCacheSize = 64

// rustExecutableKey identifies one version of an executable file. A replaced binary
// gets a new size or change time even if its inode number is reused, so it is never
// planned with another binary's symbol offsets.
type rustExecutableKey struct {
	dev        uint64
	ino        uint64
	size       int64
	changeTime int64
}

// rustExecutable is the ELF analysis shared by every process running one executable.
// It is computed once and only read afterwards.
type rustExecutable struct {
	once   sync.Once
	probes rustProbeSymbols
	err    error
}

func newRustExecutableCache() *lru.Cache[rustExecutableKey, *rustExecutable] {
	cache, _ := lru.New[rustExecutableKey, *rustExecutable](rustExecutableCacheSize)
	return cache
}

// analyzeRustExecutable returns the analysis of the opened executable, computing it
// on first use. Concurrent attaches of one binary wait for a single analysis.
func analyzeRustExecutable(cache *lru.Cache[rustExecutableKey, *rustExecutable], target *os.File) *rustExecutable {
	entry := &rustExecutable{}
	if key, ok := rustExecutableKeyOf(target); ok {
		if cached, found, _ := cache.PeekOrAdd(key, entry); found {
			entry = cached
		}
	}

	entry.once.Do(func() { entry.analyze(target) })

	return entry
}

func rustExecutableKeyOf(target *os.File) (rustExecutableKey, bool) {
	info, err := target.Stat()
	if err != nil {
		return rustExecutableKey{}, false
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return rustExecutableKey{}, false
	}

	return rustExecutableKey{dev: stat.Dev, ino: stat.Ino, size: stat.Size, changeTime: stat.Ctim.Nano()}, true
}

func (e *rustExecutable) analyze(target *os.File) {
	f, err := elf.NewFile(target)
	if err != nil {
		e.err = err
		return
	}

	e.probes, e.err = resolveRustProbes(f)
	if e.err != nil {
		return
	}

	e.err = checkRustCompiler(f)
}
