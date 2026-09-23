// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"errors"

	trackeroffsets "github.com/grafana/go-offsets-tracker/pkg/offsets"

	"go.opentelemetry.io/obi/internal/goversion"
)

const maximumRuntimeFunctionSize = 64 << 10

var ErrUnsupportedArchitecture = errors.New("stripped Go runtime global address recovery requires amd64")

// resolveRuntimeMetricSymbolsFromCode recovers runtime global addresses from Go
// machine code and applies the executable's load bias to obtain process addresses.
func resolveRuntimeMetricSymbolsFromCode(f *elf.File, loadBias uint64) (RuntimeMetricSymbols, error) {
	if f.Machine != elf.EM_X86_64 {
		return RuntimeMetricSymbols{}, ErrUnsupportedArchitecture
	}

	// Stripped binaries retain Go's function metadata after their ELF object
	// symbols are removed. It gives us the bounds of runtime functions whose
	// machine code still refers to the globals we need.
	table, err := findGoSymbolTable(f)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}

	// procresize is the anchor for gomaxprocs because it validates the current
	// processor count before changing the scheduler.
	procresize := table.LookupFunc("runtime.procresize")
	if procresize == nil {
		return RuntimeMetricSymbols{}, errors.New("runtime.procresize function not found")
	}
	if procresize.End <= procresize.Entry || procresize.End-procresize.Entry > maximumRuntimeFunctionSize {
		return RuntimeMetricSymbols{}, errors.New("invalid runtime.procresize function bounds")
	}

	code, err := readVirtualMemoryWithFlags(f, procresize.Entry, procresize.End-procresize.Entry, elf.PF_X)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}
	gomaxprocsELFAddress, err := resolveGOMAXPROCSFromCode(f, procresize.Entry, code)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}

	// We want the address of memstats.heapStats. mcache.refill passes it as the
	// receiver of acquire(), so we recover it from the instructions before the call.
	// https://github.com/golang/go/blob/go1.27.1/src/runtime/mcache.go#L160
	refill := table.LookupFunc("runtime.(*mcache).refill")
	if refill == nil {
		return RuntimeMetricSymbols{}, errors.New("runtime.(*mcache).refill function not found")
	}
	if refill.End <= refill.Entry || refill.End-refill.Entry > maximumRuntimeFunctionSize {
		return RuntimeMetricSymbols{}, errors.New("invalid runtime.(*mcache).refill function bounds")
	}
	code, err = readVirtualMemoryWithFlags(f, refill.Entry, refill.End-refill.Entry, elf.PF_X)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}
	acquire := table.LookupFunc("runtime.(*consistentHeapStats).acquire")
	if acquire == nil {
		return RuntimeMetricSymbols{}, errors.New("runtime.(*consistentHeapStats).acquire function not found")
	}
	heapStatsELFAddress, err := resolveRuntimeMetricReceiverFromCode(refill.Entry, code, acquire.Entry)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}
	heapStatsOffset, err := runtimeMetricFieldOffset(f, "runtime.mstats", "heapStats")
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}
	memstatsELFAddress, err := runtimeMetricMemstatsBase(f, heapStatsELFAddress, heapStatsOffset)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}

	// gcinit passes &gcController as the receiver of gcController.init(...).
	// https://github.com/golang/go/blob/go1.27.1/src/runtime/mgc.go#L189
	gcinit := table.LookupFunc("runtime.gcinit")
	if gcinit == nil {
		return RuntimeMetricSymbols{}, errors.New("runtime.gcinit function not found")
	}
	if gcinit.End <= gcinit.Entry || gcinit.End-gcinit.Entry > maximumRuntimeFunctionSize {
		return RuntimeMetricSymbols{}, errors.New("invalid runtime.gcinit function bounds")
	}
	code, err = readVirtualMemoryWithFlags(f, gcinit.Entry, gcinit.End-gcinit.Entry, elf.PF_X)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}
	// Go 1.18 inlines init into gcinit, leaving a call to setGCPercent.
	// Both methods receive &gcController; any matching calls must agree on it.
	var controllerMethods []uint64
	for _, name := range []string{"runtime.(*gcControllerState).init", "runtime.(*gcControllerState).setGCPercent"} {
		if method := table.LookupFunc(name); method != nil {
			controllerMethods = append(controllerMethods, method.Entry)
		}
	}
	gcControllerELFAddress, err := resolveRuntimeMetricReceiverFromCode(gcinit.Entry, code, controllerMethods...)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}
	// Validate the base of gcController; generated offsets locate its fields.
	const gcControllerAlignment = 8
	if gcControllerELFAddress%gcControllerAlignment != 0 || !runtimeMetricWritableRange(f, gcControllerELFAddress, gcControllerAlignment) {
		return RuntimeMetricSymbols{}, errors.New("invalid gcController storage")
	}

	// A PIE executable can be loaded at a different address on each run. Apply
	// that process's adjustment once, after identifying the global in the file.
	if loadBias > ^uint64(0)-gomaxprocsELFAddress {
		return RuntimeMetricSymbols{}, errors.New("gomaxprocs process address overflows")
	}
	gomaxprocsProcessAddress := loadBias + gomaxprocsELFAddress
	if loadBias > ^uint64(0)-memstatsELFAddress {
		return RuntimeMetricSymbols{}, errors.New("memstats process address overflows")
	}
	if loadBias > ^uint64(0)-gcControllerELFAddress {
		return RuntimeMetricSymbols{}, errors.New("gcController process address overflows")
	}
	// work is optional: a zero address makes the collector skip CPU statistics.
	var workProcessAddress uint64
	if workELFAddress, err := resolveRuntimeMetricWorkFromCode(f, table); err == nil && loadBias <= ^uint64(0)-workELFAddress {
		workProcessAddress = loadBias + workELFAddress
	}
	// The allocation collector requires the size-class table; failed recovery
	// leaves it disabled while preserving the mandatory runtime globals.
	var sizeClassProcessAddress uint64
	if address, err := resolveRuntimeMetricSizeClassTableFromCode(f, table); err == nil && loadBias <= ^uint64(0)-address {
		sizeClassProcessAddress = loadBias + address
	}
	// Histogram collection requires sched; keep it disabled if recovery fails.
	var schedProcessAddress uint64
	if address, err := resolveRuntimeMetricSchedFromCode(f, table); err == nil && loadBias <= ^uint64(0)-address {
		schedProcessAddress = loadBias + address
	}
	// Goroutine counting requires allglen; keep it disabled if recovery fails.
	var allgLenProcessAddress uint64
	if address, err := resolveRuntimeMetricAllgLen(f, table); err == nil && loadBias <= ^uint64(0)-address {
		allgLenProcessAddress = loadBias + address
	}
	// Goroutine counting also requires the per-P free lists reached through allp.
	var allpProcessAddress uint64
	if address, err := resolveRuntimeMetricAllp(f, table); err == nil && loadBias <= ^uint64(0)-address {
		allpProcessAddress = loadBias + address
	}
	return RuntimeMetricSymbols{
		GOMAXPROCSAddr:       gomaxprocsProcessAddress,
		MemstatsAddr:         loadBias + memstatsELFAddress,
		GCControllerAddr:     loadBias + gcControllerELFAddress,
		WorkAddr:             workProcessAddress,
		SizeClassToSizesAddr: sizeClassProcessAddress,
		SchedAddr:            schedProcessAddress,
		AllgLenAddr:          allgLenProcessAddress,
		AllpAddr:             allpProcessAddress,
	}, nil
}

// resolveRuntimeMetricWorkFromCode follows work.full.push(&b.node) in putfull.
// https://github.com/golang/go/blob/go1.27.1/src/runtime/mgcwork.go#L492
func resolveRuntimeMetricWorkFromCode(f *elf.File, table *gosym.Table) (uint64, error) {
	putfull := table.LookupFunc("runtime.putfull")
	if putfull == nil {
		return 0, errors.New("runtime.putfull function not found")
	}
	if putfull.End <= putfull.Entry || putfull.End-putfull.Entry > maximumRuntimeFunctionSize {
		return 0, errors.New("invalid runtime.putfull function bounds")
	}
	code, err := readVirtualMemoryWithFlags(f, putfull.Entry, putfull.End-putfull.Entry, elf.PF_X)
	if err != nil {
		return 0, err
	}
	push := table.LookupFunc("runtime.(*lfstack).push")
	if push == nil {
		return 0, errors.New("runtime.(*lfstack).push function not found")
	}
	fullELFAddress, err := resolveRuntimeMetricReceiverFromCode(putfull.Entry, code, push.Entry)
	if err != nil {
		return 0, err
	}
	fullOffset, err := runtimeMetricFieldOffset(f, "runtime.workType", "full")
	if err != nil {
		return 0, err
	}
	// The receiver is &work.full; subtract its field offset to recover &work.
	const fullSize = 8 // lfstack is a uint64.
	if fullELFAddress%fullSize != 0 || !runtimeMetricWritableRange(f, fullELFAddress, fullSize) {
		return 0, errors.New("invalid work.full storage")
	}
	if fullOffset >= fullELFAddress {
		return 0, errors.New("invalid work.full field offset")
	}
	workELFAddress := fullELFAddress - fullOffset
	if workELFAddress%fullSize != 0 || !runtimeMetricWritableRange(f, workELFAddress, fullOffset+fullSize) {
		return 0, errors.New("invalid work storage")
	}
	return workELFAddress, nil
}

// resolveRuntimeMetricSchedFromCode follows the atomic sched.goidgen update
// in oneNewExtraM, then subtracts its generated field offset to recover sched.
// https://github.com/golang/go/blob/go1.27.1/src/runtime/proc.go#L2523
func resolveRuntimeMetricSchedFromCode(f *elf.File, table *gosym.Table) (uint64, error) {
	function := table.LookupFunc("runtime.oneNewExtraM")
	if function == nil {
		return 0, errors.New("runtime.oneNewExtraM function not found")
	}
	if function.End <= function.Entry || function.End-function.Entry > maximumRuntimeFunctionSize {
		return 0, errors.New("invalid runtime.oneNewExtraM function bounds")
	}
	code, err := readVirtualMemoryWithFlags(f, function.Entry, function.End-function.Entry, elf.PF_X)
	if err != nil {
		return 0, err
	}
	goIDAddress, err := resolveRuntimeMetricSchedGoIDFromCode(f, function.Entry, code)
	if err != nil {
		return 0, err
	}
	goIDOffset, err := runtimeMetricFieldOffset(f, "runtime.schedt", "goidgen")
	if err != nil {
		return 0, err
	}
	return runtimeMetricSchedBase(f, goIDAddress, goIDOffset)
}

// resolveRuntimeMetricAllgLen reads allgadd's code to locate its atomic length store.
// https://github.com/golang/go/blob/go1.27.1/src/runtime/proc.go#L700
func resolveRuntimeMetricAllgLen(f *elf.File, table *gosym.Table) (uint64, error) {
	function := table.LookupFunc("runtime.allgadd")
	if function == nil {
		return 0, errors.New("runtime.allgadd function not found")
	}
	if function.End <= function.Entry || function.End-function.Entry > maximumRuntimeFunctionSize {
		return 0, errors.New("invalid runtime.allgadd function bounds")
	}
	code, err := readVirtualMemoryWithFlags(f, function.Entry, function.End-function.Entry, elf.PF_X)
	if err != nil {
		return 0, err
	}
	address, err := resolveRuntimeMetricAllgLenFromCode(f, function.Entry, code)
	if err != nil {
		return 0, err
	}
	return address, nil
}

// resolveRuntimeMetricAllp reads preemptall's code to locate the global slice
// header through its pointer and length loads and their use in the loop.
// https://github.com/golang/go/blob/go1.27.1/src/runtime/proc.go#L6894
func resolveRuntimeMetricAllp(f *elf.File, table *gosym.Table) (uint64, error) {
	function := table.LookupFunc("runtime.preemptall")
	if function == nil {
		return 0, errors.New("runtime.preemptall function not found")
	}
	if function.End <= function.Entry || function.End-function.Entry > maximumRuntimeFunctionSize {
		return 0, errors.New("invalid runtime.preemptall function bounds")
	}
	code, err := readVirtualMemoryWithFlags(f, function.Entry, function.End-function.Entry, elf.PF_X)
	if err != nil {
		return 0, err
	}
	address, err := resolveRuntimeMetricAllpFromCode(f, function.Entry, code)
	if err != nil {
		return 0, err
	}
	return address, nil
}

// runtimeMetricMemstatsBase moves from &memstats.heapStats back to memstats.
// The range through the first 64-bit heapStats field must fit writable memory.
func runtimeMetricMemstatsBase(f *elf.File, heapStatsELFAddress, heapStatsOffset uint64) (uint64, error) {
	const heapStatsCounterSize = 8
	if heapStatsELFAddress%heapStatsCounterSize != 0 || !runtimeMetricWritableRange(f, heapStatsELFAddress, heapStatsCounterSize) {
		return 0, errors.New("invalid memstats.heapStats storage")
	}
	if heapStatsOffset >= heapStatsELFAddress {
		return 0, errors.New("invalid memstats.heapStats field offset")
	}
	memstatsELFAddress := heapStatsELFAddress - heapStatsOffset
	if memstatsELFAddress%heapStatsCounterSize != 0 || !runtimeMetricWritableRange(f, memstatsELFAddress, heapStatsOffset+heapStatsCounterSize) {
		return 0, errors.New("invalid memstats storage")
	}
	return memstatsELFAddress, nil
}

// runtimeMetricSchedBase moves from &sched.goidgen back to the sched global.
// The range from the base through the eight-byte field must fit writable memory.
func runtimeMetricSchedBase(f *elf.File, goIDAddress, goIDOffset uint64) (uint64, error) {
	const goIDSize = 8
	if goIDAddress%goIDSize != 0 || !runtimeMetricWritableRange(f, goIDAddress, goIDSize) {
		return 0, errors.New("invalid sched.goidgen storage")
	}
	if goIDOffset >= goIDAddress {
		return 0, errors.New("invalid sched.goidgen field offset")
	}
	schedAddress := goIDAddress - goIDOffset
	if schedAddress%goIDSize != 0 || !runtimeMetricWritableRange(f, schedAddress, goIDOffset+goIDSize) {
		return 0, errors.New("invalid sched storage")
	}
	return schedAddress, nil
}

// runtimeMetricFieldOffset locates a field for the target's Go version.
// A missing generated offset is an error; a zero offset is valid.
func runtimeMetricFieldOffset(f *elf.File, structName, fieldName string) (uint64, error) {
	versionString, _, err := getGoDetails(f)
	if err != nil {
		return 0, err
	}
	version, err := goversion.Parse(versionString)
	if err != nil {
		return 0, err
	}
	track, err := trackeroffsets.Read(bytes.NewBufferString(prefetchedOffsets))
	if err != nil {
		return 0, err
	}
	return generatedABIFact(track, structName, fieldName, version)
}

// runtimeMetricWritableRange checks that the whole global fits in a readable,
// writable load segment. It uses the segment's in-memory size so zero-initialized
// globals in BSS remain valid even when the ELF stores no bytes for them.
func runtimeMetricWritableRange(f *elf.File, address, size uint64) bool {
	if size == 0 || size > ^uint64(0)-address {
		return false
	}
	for _, prog := range f.Progs {
		const requiredFlags = elf.PF_R | elf.PF_W
		if prog.Type != elf.PT_LOAD || prog.Flags&requiredFlags != requiredFlags || address < prog.Vaddr {
			continue
		}
		if prog.Memsz > ^uint64(0)-prog.Vaddr {
			continue
		}
		// Subtract only after checking the lower bound; avoid adding range ends.
		offset := address - prog.Vaddr
		if offset < prog.Memsz && size <= prog.Memsz-offset {
			return true
		}
	}
	return false
}
