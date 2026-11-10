// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
)

// GoFrame is one call frame of a symbolized Go stack.
type GoFrame struct {
	Function string
	File     string
	Line     int
}

// GoSymbolResolver symbolizes executable PCs with the ebpf-profiler reader of
// the Go PC table, which maps the executable read-only.
type GoSymbolResolver struct {
	mu         sync.RWMutex
	elf        *pfelf.File
	executable *elf.File
	goVersion  string
	table      *elfunwindinfo.Gopclntab
	textOnce   sync.Once
	textBase   uint64
	textErr    error
	valueTypes *simplelru.LRU[uint64, GoValueType]
}

// runtimeTextBase resolves the base used by Go method code offsets once per
// executable. The caller holds r.mu while accessing the executable.
func (r *GoSymbolResolver) runtimeTextBase() (uint64, error) {
	r.textOnce.Do(func() {
		section := r.executable.Section(".gopclntab")
		r.textBase, r.textErr = findRuntimeText(r.executable, section, nil)
		if r.textErr != nil && section != nil {
			data, err := section.Data()
			if err == nil {
				r.textBase, r.textErr = findRuntimeTextFromPclntab(data)
			}
		}
	})
	return r.textBase, r.textErr
}

// NewGoSymbolResolver maps file until Close, but does not take ownership of it.
func NewGoSymbolResolver(file *os.File) (*GoSymbolResolver, error) {
	executable, err := elf.NewFile(file)
	if err != nil {
		return nil, err
	}
	goVersion, _, _ := getGoDetails(executable)
	resolver, err := newGoSymbolResolver(func() (*pfelf.File, error) {
		return pfelf.NewFile(file, 0, false)
	})
	if err != nil {
		return nil, err
	}
	resolver.executable = executable
	resolver.goVersion = goVersion
	return resolver, nil
}

func newGoSymbolResolver(openELF func() (*pfelf.File, error)) (resolver *GoSymbolResolver, err error) {
	previousPanicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(previousPanicOnFault)
	defer func() {
		if value := recover(); value != nil {
			if _, ok := value.(goMappedMemoryFault); !ok {
				panic(value)
			}
			resolver, err = nil, fmt.Errorf("go symbol mapping fault: %v", value)
		}
	}()

	elfFile, err := openELF()
	if err != nil {
		return nil, err
	}
	defer func() {
		if resolver == nil {
			_ = elfFile.Close()
		}
	}()
	table, err := elfunwindinfo.NewGopclntab(elfFile)
	if err != nil {
		return nil, err
	}
	return &GoSymbolResolver{elf: elfFile, table: table}, nil
}

// A retained executable mapping can fault after the process exits and its
// backing inode is truncated. Bounds and other programming panics still escape.
type goMappedMemoryFault interface {
	runtime.Error
	Addr() uintptr
}

// PCToFrame returns the frame of a call PC, or false when the PC is unknown or
// the executable was truncated.
func (r *GoSymbolResolver) PCToFrame(pc uint64) (frame GoFrame, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.pcToFrame(pc)
}

// pcToFrame requires the caller to hold r.mu while accessing the mapping.
func (r *GoSymbolResolver) pcToFrame(pc uint64) (frame GoFrame, ok bool) {
	if r.table == nil {
		return GoFrame{}, false
	}

	previousPanicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(previousPanicOnFault)
	defer func() {
		if value := recover(); value != nil {
			if _, ok := value.(goMappedMemoryFault); !ok {
				panic(value)
			}
			frame, ok = GoFrame{}, false
		}
	}()

	file, line, function := r.table.Symbolize(uintptr(pc))
	if function == "" || file == "" || line == 0 {
		return GoFrame{}, false
	}
	// Symbolize returns strings that alias the mapping, which Close unmaps.
	return GoFrame{Function: strings.Clone(function), File: strings.Clone(file), Line: int(line)}, true
}

// ReadOnlyData reads file-backed bytes at an executable-relative virtual address.
// Read-only segments let callers recover constant messages from the executable
// when BPF could not read their pages in the process.
func (r *GoSymbolResolver) ReadOnlyData(addr, size uint64) ([]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.table == nil {
		return nil, false
	}
	data, err := readVirtualMemoryWithPermissions(r.executable, addr, size, elf.PF_R, elf.PF_W)
	return data, err == nil
}

// SetDontNeed drops the mapped pages from the process RSS. Later lookups fault
// back in only the pages they read.
func (r *GoSymbolResolver) SetDontNeed() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.table != nil {
		_ = r.table.SetDontNeed()
	}
}

func (r *GoSymbolResolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.table == nil {
		return nil
	}
	err := r.table.Close()
	if closeErr := r.elf.Close(); err == nil {
		err = closeErr
	}
	r.table = nil
	r.valueTypes = nil
	r.elf = nil
	return err
}
