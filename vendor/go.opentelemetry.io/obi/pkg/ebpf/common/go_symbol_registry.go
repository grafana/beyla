// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

type goExecutableID struct {
	device uint64
	inode  uint64
}

type goSymbolTableEntry struct {
	mu         sync.Mutex
	file       *os.File
	resolver   GoSymbolResolver
	loadError  error
	retryAfter time.Time
	closed     bool
}

// GoSymbolResolver reads frames, panic types and constant data using executable-
// relative addresses. Close releases its backing storage once the executable
// is no longer instrumented.
type GoSymbolResolver interface {
	PCToFrame(uint64) (goexec.GoFrame, bool)
	ValueType(uint64) (goexec.GoValueType, bool)
	ReadOnlyData(addr, size uint64) ([]byte, bool)
	// SetDontNeed releases memory the resolver can reload on its next lookup.
	SetDontNeed()
	Close() error
}

type goPIDSymbolBinding struct {
	executable goExecutableID
	loadBias   uint64
}

// GoSymbolRegistry shares lazy executable resolvers across processes while
// retaining each process's executable load bias.
type GoSymbolRegistry struct {
	mu          sync.RWMutex
	executables map[goExecutableID]*goSymbolTableEntry
	pids        map[app.PID]goPIDSymbolBinding
}

func NewGoSymbolRegistry() *GoSymbolRegistry {
	return &GoSymbolRegistry{
		executables: map[goExecutableID]*goSymbolTableEntry{},
		pids:        map[app.PID]goPIDSymbolBinding{},
	}
}

// AddExecutable retains the executable file and loads its symbol table on first use.
func (r *GoSymbolRegistry) AddExecutable(info *exec.FileInfo) error {
	if r == nil {
		return errors.New("go symbol registry is nil")
	}

	if info == nil {
		return errors.New("executable info is nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.initMaps()
	key := goExecutableID{device: info.Dev(), inode: info.Ino()}
	if _, ok := r.executables[key]; ok {
		return nil
	}

	file, err := info.OpenExecutable()
	if err != nil {
		return fmt.Errorf("opening Go executable: %w", err)
	}
	r.executables[key] = &goSymbolTableEntry{file: file}
	return nil
}

// RemoveExecutable releases the executable's symbol table, waiting for any
// lookup that is still using it.
func (r *GoSymbolRegistry) RemoveExecutable(device, inode uint64) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := goExecutableID{device: device, inode: inode}
	if entry, ok := r.executables[key]; ok {
		entry.close()
		delete(r.executables, key)
	}
}

// BindPID maps a process to its executable and the address it is loaded at.
func (r *GoSymbolRegistry) BindPID(pid app.PID, device, inode, loadBias uint64) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.initMaps()
	r.pids[pid] = goPIDSymbolBinding{executable: goExecutableID{device: device, inode: inode}, loadBias: loadBias}
}

func (r *GoSymbolRegistry) RemovePID(pid app.PID) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.pids, pid)
}

// Frames resolves runtime return PCs for an exact host PID, innermost first.
// Resolution stops at the first zero or unknown PC and retains preceding frames.
func (r *GoSymbolRegistry) Frames(pid app.PID, pcs []uint64) ([]goexec.GoFrame, error) {
	entry, loadBias, err := r.lockEntry(pid)
	if err != nil {
		return nil, err
	}
	defer entry.mu.Unlock()
	defer func() {
		if entry.resolver != nil {
			entry.resolver.SetDontNeed()
		}
	}()
	if len(pcs) == 0 || pcs[0] == 0 || pcs[0] <= loadBias {
		return nil, nil
	}
	if err := entry.openResolver(); err != nil {
		return nil, err
	}

	var stack []goexec.GoFrame
	// A return address follows its call, so the call's line is one byte back.
	callOffset := uint64(1)
	for _, runtimePC := range pcs {
		if runtimePC == 0 || runtimePC <= loadBias {
			break
		}

		frame, ok := entry.resolver.PCToFrame(runtimePC - loadBias - callOffset)
		if !ok {
			break
		}
		// The caller of runtime.sigpanic faulted at its PC instead of calling.
		callOffset = 1
		if frame.Function == "runtime.sigpanic" {
			callOffset = 0
		}
		// Skip error constructors captured as the innermost frames.
		if len(stack) == 0 && goErrorHelper(frame.Function) {
			continue
		}
		stack = append(stack, frame)
	}
	return stack, nil
}

// PanicValueType translates a runtime type address using the PID's load bias
// and reads its metadata from that process's executable.
func (r *GoSymbolRegistry) PanicValueType(pid app.PID, typeAddr uint64) (goexec.GoValueType, bool) {
	entry, loadBias, err := r.lockEntry(pid)
	if err != nil {
		return goexec.GoValueType{}, false
	}
	defer entry.mu.Unlock()
	if typeAddr == 0 || typeAddr <= loadBias {
		return goexec.GoValueType{}, false
	}
	if err := entry.openResolver(); err != nil {
		return goexec.GoValueType{}, false
	}
	return entry.resolver.ValueType(typeAddr - loadBias)
}

// ReadOnlyData translates a runtime address using the PID's load bias and reads
// constant bytes from that process's executable.
func (r *GoSymbolRegistry) ReadOnlyData(pid app.PID, addr, size uint64) ([]byte, bool) {
	entry, loadBias, err := r.lockEntry(pid)
	if err != nil {
		return nil, false
	}
	defer entry.mu.Unlock()
	if addr == 0 || addr <= loadBias {
		return nil, false
	}
	if err := entry.openResolver(); err != nil {
		return nil, false
	}
	return entry.resolver.ReadOnlyData(addr-loadBias, size)
}

// lockEntry pins the PID's executable while a lookup uses its resolver.
// The caller releases entry.mu when the lookup finishes.
func (r *GoSymbolRegistry) lockEntry(pid app.PID) (*goSymbolTableEntry, uint64, error) {
	if r == nil {
		return nil, 0, errors.New("go symbol registry is nil")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	binding, ok := r.pids[pid]
	if !ok {
		return nil, 0, fmt.Errorf("go symbol binding not found for PID %d", pid)
	}
	entry, ok := r.executables[binding.executable]
	if !ok || entry == nil {
		return nil, 0, fmt.Errorf("go symbol table not found for PID %d", pid)
	}
	entry.mu.Lock()
	return entry, binding.loadBias, nil
}

// openResolver shares the lazy resolver and its retry delay across lookups.
// The caller holds entry.mu for the duration of the lookup.
func (entry *goSymbolTableEntry) openResolver() error {
	if entry.resolver != nil {
		return nil
	}
	if entry.loadError != nil && time.Now().Before(entry.retryAfter) {
		return entry.loadError
	}
	resolver, err := goexec.NewGoSymbolResolver(entry.file)
	if err != nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		entry.loadError = err
		entry.retryAfter = time.Now().Add(time.Second)
		return err
	}
	entry.resolver = resolver
	entry.loadError = nil
	return nil
}

func (r *GoSymbolRegistry) initMaps() {
	if r.executables == nil {
		r.executables = map[goExecutableID]*goSymbolTableEntry{}
	}
	if r.pids == nil {
		r.pids = map[app.PID]goPIDSymbolBinding{}
	}
}

func (entry *goSymbolTableEntry) close() {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.closed {
		return
	}
	entry.closed = true
	if entry.resolver != nil {
		_ = entry.resolver.Close()
		entry.resolver = nil
	}
	if entry.file != nil {
		_ = entry.file.Close()
		entry.file = nil
	}
}

// Close releases remaining executable files and resolvers when the event pipeline stops.
func (r *GoSymbolRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, entry := range r.executables {
		entry.close()
	}
	clear(r.executables)
	clear(r.pids)
	return nil
}

func goErrorHelper(function string) bool {
	switch function {
	case "fmt.Errorf", "fmt.errorf", "errors.New", "runtime.gopanic":
		return true
	default:
		return false
	}
}
