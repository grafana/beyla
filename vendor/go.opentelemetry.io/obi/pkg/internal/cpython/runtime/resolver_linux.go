// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const maxRuntimeObjectCandidates = 4

var (
	errRuntimeNotFound          = errors.New("CPython runtime not found")
	errRuntimeObjectUnavailable = errors.New("CPython runtime object unavailable")
	errProcessReplaced          = errors.New("CPython process replaced")
	legacyVersionPattern        = regexp.MustCompile(`3\.(9|10)\.(\d{1,3})`)
)

// Resolve locates CPython and returns a validated metric target.
func (r *Resolver) Resolve(ctx context.Context, pid app.PID, expectedStartTime uint64) (*MetricTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return nil, err
	}
	stat, err := proc.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Starttime != expectedStartTime {
		return nil, errProcessReplaced
	}
	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("reading CPython process maps: %w", err)
	}
	objects, err := runtimeObjectCandidates(pid, maps)
	if err != nil {
		return nil, err
	}
	return resolveRuntimeObjectCandidates(pid, objects, func(object *procfs.ProcMap) (*MetricTarget, error) {
		return r.resolveMappedObject(pid, expectedStartTime, maps, object)
	})
}

// ProcessStartTime returns the procfs lifecycle identity for one PID.
func ProcessStartTime(pid app.PID) (uint64, error) {
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return 0, err
	}
	stat, err := proc.Stat()
	if err != nil {
		return 0, err
	}
	return stat.Starttime, nil
}

// resolveRuntimeObjectCandidates requires one runtime owner and gives operational errors precedence over compatibility results.
func resolveRuntimeObjectCandidates(
	pid app.PID,
	objects []*procfs.ProcMap,
	resolve func(*procfs.ProcMap) (*MetricTarget, error),
) (*MetricTarget, error) {
	var targets []*MetricTarget
	var operationalErr, unsupportedErr error
	for _, object := range objects {
		target, resolveErr := resolve(object)
		if resolveErr == nil {
			targets = append(targets, target)
			continue
		}
		switch {
		case errors.Is(resolveErr, errRuntimeNotFound):
			if isLibPythonMapping(object) {
				unsupportedErr = fmt.Errorf("%w: missing runtime anchor", errUnsupportedLayout)
			}
		case errors.Is(resolveErr, errUnsupportedLayout):
			unsupportedErr = resolveErr
		default:
			operationalErr = resolveErr
		}
	}

	if operationalErr != nil {
		closeMetricTargets(targets)
		return nil, fmt.Errorf("resolving CPython runtime for PID %d: %w", pid, operationalErr)
	}
	if len(targets) > 1 {
		closeMetricTargets(targets)
		return nil, fmt.Errorf("%w: multiple mapped objects own a supported CPython runtime", errUnsupportedLayout)
	}
	if len(targets) == 1 {
		return targets[0], nil
	}
	if unsupportedErr != nil {
		return nil, unsupportedErr
	}
	return nil, fmt.Errorf("%w for PID %d", errRuntimeNotFound, pid)
}

func closeMetricTargets(targets []*MetricTarget) {
	for _, target := range targets {
		_ = target.Close()
	}
}

// resolveMappedObject combines cached image analysis with PID-specific load bias and lifecycle checks.
func (r *Resolver) resolveMappedObject(
	pid app.PID,
	startTime uint64,
	maps []*procfs.ProcMap,
	object *procfs.ProcMap,
) (*MetricTarget, error) {
	opened, err := openMappedELF(pid, object)
	if err != nil {
		return nil, err
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = opened.file.Close()
		}
	}()

	key := mappedObjectKey{device: object.Dev, inode: object.Inode}
	analysis, err := r.analysisCache.getOrAnalyze(key, func() (*elfAnalysis, error) {
		return r.analyzeMappedELF(opened.elf)
	})
	if err != nil {
		return nil, err
	}
	loadBias, err := procs.FindMappingLoadBias(maps, opened.elf.Progs, object.Dev, object.Inode)
	if err != nil {
		return nil, err
	}
	runtimeAddress, err := checkedAddress(loadBias, analysis.anchor)
	if err != nil {
		return nil, err
	}
	currentStartTime, err := ProcessStartTime(pid)
	if err != nil {
		return nil, err
	}
	if currentStartTime != startTime {
		return nil, errProcessReplaced
	}

	target := &MetricTarget{
		PID:                     pid,
		StartTime:               startTime,
		Device:                  object.Dev,
		Inode:                   object.Inode,
		RuntimeAddress:          runtimeAddress,
		RuntimeFinalizing:       analysis.profile.runtimeFinalizing,
		RuntimeInterpretersMain: analysis.profile.runtimeInterpretersMain,
		InterpreterGC:           analysis.profile.interpreterGC,
		GCGenerationStats:       analysis.profile.gcGenerationStats,
		PrimaryProbe:            analysis.primaryProbe,
		attachment:              opened.file,
	}
	if analysis.fallbackProbe != nil && analysis.primaryProbe.Kind == GCCompletionProbeUSDT {
		fallback := *analysis.fallbackProbe
		target.FallbackProbe = &fallback
	}
	keepOpen = true
	return target, nil
}

// analyzeMappedELF prefers USDT and keeps a safe private probe for attachment fallback when available.
func (*Resolver) analyzeMappedELF(file *elf.File) (*elfAnalysis, error) {
	if !supportedELF(file) {
		return nil, errUnsupportedLayout
	}
	objects, err := procs.FindExeSymbols(file, []string{"_PyRuntime", "Py_Version"}, elf.STT_OBJECT)
	if err != nil {
		return nil, fmt.Errorf("reading CPython symbols: %w", err)
	}
	anchor, ok := runtimeAnchor(file, objects)
	if !ok {
		return nil, errRuntimeNotFound
	}
	analysis := &elfAnalysis{anchor: anchor}
	if symbol, ok := objects["Py_Version"]; ok {
		analysis.versionAddress = symbol.Value
	}

	version, freeThreaded, debugPrefix, err := runtimeVersionFromELF(file, analysis)
	if err != nil {
		return nil, err
	}
	profile, ok := selectLayout(version, freeThreaded)
	if !ok {
		return nil, fmt.Errorf("%w: CPython %s", errUnsupportedLayout, versionFromHex(version))
	}
	if profile.debugGCOffset != 0 {
		gcDebugAddress, addressErr := checkedAddress(anchor, profile.debugGCOffset)
		if addressErr != nil {
			return nil, addressErr
		}
		gcDebug, readErr := readVirtualBytes(file, gcDebugAddress, inlineDebugGCSize)
		if readErr != nil {
			return nil, readErr
		}
		profile, err = resolveDebugLayout(profile, debugPrefix, gcDebug)
		if err != nil {
			return nil, err
		}
	}
	analysis.profile = profile

	usdt, err := findPythonGCDoneUSDT(file)
	if err != nil {
		return nil, err
	}
	var private *GCCompletionProbe
	privateProbe, privateErr := findPrivateCollectorProbe(file)
	if privateErr == nil {
		private = &privateProbe
	} else if usdt == nil {
		return nil, privateErr
	}

	switch {
	case usdt != nil:
		analysis.primaryProbe = *usdt
		analysis.fallbackProbe = private
	case private != nil:
		analysis.primaryProbe = *private
	default:
		return nil, fmt.Errorf("%w: no safe CPython GC completion probe", errUnsupportedLayout)
	}
	return analysis, nil
}

// runtimeVersionFromELF prefers debug metadata, then Py_Version, then a legacy .rodata string.
func runtimeVersionFromELF(file *elf.File, analysis *elfAnalysis) (uint32, bool, []byte, error) {
	prefix, err := readVirtualBytes(file, analysis.anchor, uint64(debugOffsets.PrefixSize))
	if err == nil && string(prefix[:len(debugOffsets.Cookie)]) == debugOffsets.Cookie {
		version := binary.LittleEndian.Uint64(prefix[debugOffsets.Version:])
		freeThreaded := binary.LittleEndian.Uint64(prefix[debugOffsets.FreeThreaded:])
		if version > math.MaxUint32 || freeThreaded > 1 {
			return 0, false, nil, errUnsupportedLayout
		}
		return uint32(version), freeThreaded == 1, prefix, nil
	}
	if analysis.versionAddress != 0 {
		value, readErr := readVirtualBytes(file, analysis.versionAddress, 4)
		if readErr != nil {
			return 0, false, nil, readErr
		}
		return binary.LittleEndian.Uint32(value), false, nil, nil
	}
	if version, ok := legacyVersionFromELF(file); ok {
		return version, false, nil, nil
	}
	if err != nil {
		return 0, false, nil, err
	}
	return 0, false, nil, errUnsupportedLayout
}

func readVirtualBytes(file *elf.File, address, size uint64) ([]byte, error) {
	if size == 0 || size > math.MaxInt {
		return nil, errUnsupportedLayout
	}
	var match *elf.Prog
	for _, program := range file.Progs {
		// Require the complete range to be file-backed by one loadable segment.
		// The subtraction form keeps the unsigned bounds checks overflow-safe.
		if program.Type != elf.PT_LOAD || address < program.Vaddr || size > program.Filesz ||
			address-program.Vaddr > program.Filesz-size {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("%w: virtual address belongs to multiple file segments", errUnsupportedLayout)
		}
		match = program
	}
	if match == nil {
		return nil, fmt.Errorf("%w: virtual address is not file-backed", errUnsupportedLayout)
	}
	data := make([]byte, int(size))
	offset := match.Off + address - match.Vaddr
	read, err := match.ReadAt(data, int64(offset-match.Off))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if read != len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func runtimeObjectCandidates(pid app.PID, maps []*procfs.ProcMap) ([]*procfs.ProcMap, error) {
	executableInfo, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}
	stat, ok := executableInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errUnsupportedLayout
	}

	seen := map[[2]uint64]struct{}{}
	objects := make([]*procfs.ProcMap, 0, 2)
	for _, mapping := range maps {
		isExecutable := mapping.Dev == stat.Dev && mapping.Inode == stat.Ino
		if mapping.Inode == 0 || (!isExecutable && !isLibPythonMapping(mapping)) {
			continue
		}
		key := [2]uint64{mapping.Dev, mapping.Inode}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		objects = append(objects, mapping)
		if len(objects) == maxRuntimeObjectCandidates {
			break
		}
	}
	return objects, nil
}

func isLibPythonMapping(mapping *procfs.ProcMap) bool {
	base := filepath.Base(strings.TrimSuffix(mapping.Pathname, " (deleted)"))
	return strings.HasPrefix(base, "libpython3.") && strings.Contains(base, ".so")
}

type mappedELF struct {
	file *os.File
	elf  *elf.File
}

// openMappedELF opens the mapped object through map_files when possible.
// Its path fallback requires the same device and inode.
func openMappedELF(pid app.PID, object *procfs.ProcMap) (*mappedELF, error) {
	mapFile := fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, object.StartAddr, object.EndAddr)
	if backing, err := os.Open(mapFile); err == nil {
		parsed, parseErr := elf.NewFile(backing)
		if parseErr == nil {
			return &mappedELF{file: backing, elf: parsed}, nil
		}
		_ = backing.Close()
	}

	path := strings.TrimSuffix(object.Pathname, " (deleted)")
	if filepath.IsAbs(path) {
		path = filepath.Join(fmt.Sprintf("/proc/%d/root", pid), path)
	}
	backing, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: opening mapped CPython object: %w", errRuntimeObjectUnavailable, err)
	}
	info, err := backing.Stat()
	if err != nil {
		_ = backing.Close()
		return nil, fmt.Errorf("stating mapped CPython object: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev != object.Dev || stat.Ino != object.Inode {
		_ = backing.Close()
		return nil, fmt.Errorf("%w: mapped CPython object identity changed", errUnsupportedLayout)
	}
	parsed, err := elf.NewFile(backing)
	if err != nil {
		_ = backing.Close()
		return nil, fmt.Errorf("opening verified CPython object: %w", err)
	}
	return &mappedELF{file: backing, elf: parsed}, nil
}

func supportedELF(file *elf.File) bool {
	return file != nil && file.Class == elf.ELFCLASS64 && file.Data == elf.ELFDATA2LSB &&
		(file.Machine == elf.EM_X86_64 || file.Machine == elf.EM_AARCH64)
}

func runtimeAnchor(file *elf.File, symbols map[string]procs.Sym) (uint64, bool) {
	if section := file.Section(".PyRuntime"); section != nil && section.Addr != 0 {
		return section.Addr, true
	}
	if symbol, ok := symbols["_PyRuntime"]; ok && symbol.Value != 0 {
		return symbol.Value, true
	}
	return 0, false
}

func legacyVersionFromELF(file *elf.File) (uint32, bool) {
	section := file.Section(".rodata")
	if section == nil || section.Size == 0 || section.Size > 64<<20 {
		return 0, false
	}
	data, err := section.Data()
	if err != nil {
		return 0, false
	}
	return parseLegacyVersion(data)
}

func parseLegacyVersion(data []byte) (uint32, bool) {
	var version uint32
	for _, match := range legacyVersionPattern.FindAllSubmatchIndex(data, -1) {
		start, end := match[0], match[1]
		if start != 0 && data[start-1] != 0 {
			continue
		}
		hasNullTerminator := end < len(data) && data[end] == 0
		hasBuildInfo := end+1 < len(data) && data[end] == ' ' && data[end+1] == '('
		if !hasNullTerminator && !hasBuildInfo {
			continue
		}

		minor, err := strconv.ParseUint(string(data[match[2]:match[3]]), 10, 8)
		if err != nil {
			return 0, false
		}
		micro, err := strconv.ParseUint(string(data[match[4]:match[5]]), 10, 8)
		if err != nil {
			return 0, false
		}
		candidate := uint32(3)<<24 | uint32(minor)<<16 | uint32(micro)<<8 | 0xf0
		if version != 0 && candidate != version {
			return 0, false
		}
		version = candidate
	}
	return version, version != 0
}

func checkedAddress(base, offset uint64) (uint64, error) {
	address := base + offset
	if address < base {
		return 0, errUnsupportedLayout
	}
	return address, nil
}
