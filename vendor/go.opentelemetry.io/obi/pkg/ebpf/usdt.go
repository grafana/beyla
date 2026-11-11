// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

const (
	obiUSDTMaxArgs             = 12
	obiUSDTMaxSpecCnt          = 256
	obiUSDTNoteType            = 3
	obiUSDTNoteName            = "stapsdt"
	obiUSDTArgConst            = uint8(0)
	obiUSDTArgReg              = uint8(1)
	obiUSDTArgRegDeref         = uint8(2)
	obiUSDTArgRegDerefStr      = uint8(3)
	obiUSDTArgGoString         = uint8(4)
	obiUSDTArgPtrFieldGoString = uint8(5) // reg = *struct; string at {struct+val_off, +8}
)

// TODO: Reevaluate github.com/parca-dev/usdt if it exposes target-ELF-driven
// argument parsing for OBI's BPF ABI. v0.0.2 uses runtime.GOARCH for register
// parsing, uses a different spec layout, and its note parser assumes
// little-endian ELF64 notes.

type usdtNote struct {
	Location  uint64
	Base      uint64
	Semaphore uint64
	Provider  string
	Name      string
	Args      string
}

type sdtHeader struct {
	NameSize uint32
	DescSize uint32
	Type     uint32
}

type usdtNoteHeader32 struct {
	Location  uint32
	Base      uint32
	Semaphore uint32
}

type usdtNoteHeader64 struct {
	Location  uint64
	Base      uint64
	Semaphore uint64
}

type obiUSDTArgSpec struct {
	ValOff      uint64
	RegOff      int16
	ArgType     uint8
	ArgSigned   uint8
	ArgBitshift uint8
	_           [3]byte
}

// obiUSDTMatchNameLen mirrors k_obi_usdt_match_name_len in usdt_types.h.
const obiUSDTMatchNameLen = 64

// obiUSDTPair{Tid,G} mirror k_obi_usdt_pair_*. _arg0 (=0) is the implicit
// USDT pairing on arg_int[0]; no Go constant needed.
const (
	obiUSDTPairTid = uint8(1)
	obiUSDTPairG   = uint8(2)
)

type obiUSDTSpec struct {
	Args           [obiUSDTMaxArgs]obiUSDTArgSpec
	Cookie         uint64
	ArgCount       uint16
	PairKind       uint8
	MatchArgIdx    uint8
	MatchEnabled   uint8
	_              [3]byte
	MatchName      [obiUSDTMatchNameLen]byte
	ReturnArgs     [obiUSDTMaxArgs]obiUSDTArgSpec
	ReturnArgCount uint16
	_              [6]byte
}

type obiUSDTIPKey struct {
	PID       uint32
	Namespace uint32
	IP        uint64
}

type usdtTarget struct {
	AbsIP   uint64
	RelIP   uint64
	SemaOff uint64
	Spec    obiUSDTSpec
	SpecKey string
	// ReturnRelIPs holds per-instruction RET offsets when the target
	// binary is Go. Kernel uretprobe on Go is unsafe (the trampoline
	// rewrites the on-stack return address, which the Go GC walks and
	// can mistake for a heap pointer), so for Go function_span we attach
	// regular uprobes at each RET site instead — same approach as the
	// gotracer in pkg/internal/ebpf/gotracer.
	ReturnRelIPs []uint64
}

// USDTProbeTarget contains the file offsets needed to attach one USDT probe.
type USDTProbeTarget struct {
	FileOffset      uint64
	SemaphoreOffset uint64
}

var (
	errUnsupportedUSDTArch = errors.New("unsupported USDT architecture")

	usdtNumberRE     = `[+-]?(?:0x[0-9A-Fa-f]+|\d+)`
	x86RegDerefArgRE = regexp.MustCompile(`^\s*([+-]?\d+)\s*@\s*(` + usdtNumberRE + `)?\s*\(\s*%([A-Za-z0-9]+)\s*\)\s*`)
	x86RegArgRE      = regexp.MustCompile(`^\s*([+-]?\d+)\s*@\s*%([A-Za-z0-9]+)\s*`)
	x86ConstArgRE    = regexp.MustCompile(`^\s*([+-]?\d+)\s*@\s*\$(` + usdtNumberRE + `)\s*`)

	arm64RegDerefArgRE = regexp.MustCompile(`^\s*([+-]?\d+)\s*@\s*\[\s*([A-Za-z0-9]+)\s*(?:,\s*(` + usdtNumberRE + `)\s*)?\]\s*`)
	arm64RegArgRE      = regexp.MustCompile(`^\s*([+-]?\d+)\s*@\s*([A-Za-z][A-Za-z0-9]*)\s*`)
	arm64ConstArgRE    = regexp.MustCompile(`^\s*([+-]?\d+)\s*@\s*(` + usdtNumberRE + `)\s*`)
)

func parseUSDTNote(class elf.Class, order binary.ByteOrder, desc []byte) (usdtNote, error) {
	addrsLen := usdtNoteHeaderLen(class)
	if addrsLen == 0 {
		return usdtNote{}, fmt.Errorf("unsupported ELF class %s", class)
	}
	if len(desc) < addrsLen+3 {
		return usdtNote{}, fmt.Errorf("USDT note descriptor too short: %d", len(desc))
	}

	note := usdtNote{}
	if err := readUSDTNoteHeader(class, order, desc[:addrsLen], &note); err != nil {
		return usdtNote{}, err
	}

	fields := strings.SplitN(string(desc[addrsLen:]), "\x00", 4)
	if len(fields) < 4 || fields[0] == "" || fields[1] == "" {
		return usdtNote{}, errors.New("invalid USDT note string fields")
	}
	note.Provider = fields[0]
	note.Name = fields[1]
	note.Args = fields[2]

	return note, nil
}

func usdtNoteHeaderLen(class elf.Class) int {
	switch class {
	case elf.ELFCLASS32:
		return binary.Size(usdtNoteHeader32{})
	case elf.ELFCLASS64:
		return binary.Size(usdtNoteHeader64{})
	default:
		return 0
	}
}

func readUSDTNoteHeader(class elf.Class, order binary.ByteOrder, header []byte, note *usdtNote) error {
	switch class {
	case elf.ELFCLASS32:
		var raw usdtNoteHeader32
		if err := binary.Read(bytes.NewReader(header), order, &raw); err != nil {
			return err
		}
		note.Location = uint64(raw.Location)
		note.Base = uint64(raw.Base)
		note.Semaphore = uint64(raw.Semaphore)
	case elf.ELFCLASS64:
		var raw usdtNoteHeader64
		if err := binary.Read(bytes.NewReader(header), order, &raw); err != nil {
			return err
		}
		note.Location = raw.Location
		note.Base = raw.Base
		note.Semaphore = raw.Semaphore
	default:
		return fmt.Errorf("unsupported ELF class %s", class)
	}
	return nil
}

func readSDTHeader(order binary.ByteOrder, data []byte) (sdtHeader, error) {
	var header sdtHeader
	if err := binary.Read(bytes.NewReader(data), order, &header); err != nil {
		return sdtHeader{}, err
	}
	return header, nil
}

// FindUSDTProbeTargets finds all matching probes in an ELF file.
func FindUSDTProbeTargets(elfFile *elf.File, provider, name string) ([]USDTProbeTarget, error) {
	parsedTargets, err := collectUSDTTargets(elfFile, 0, nil, "", provider, name)
	if err != nil {
		return nil, err
	}

	targets := make([]USDTProbeTarget, 0, len(parsedTargets))
	for _, target := range parsedTargets {
		if target.SemaOff > math.MaxUint32 {
			return nil, errors.New("USDT semaphore offset exceeds uint32")
		}
		targets = append(targets, USDTProbeTarget{
			FileOffset:      target.RelIP,
			SemaphoreOffset: target.SemaOff,
		})
	}
	return targets, nil
}

func collectUSDTTargets(
	elfFile *elf.File,
	pid app.PID,
	maps []*procfs.ProcMap,
	mappedPath string,
	provider string,
	name string,
) ([]usdtTarget, error) {
	notes := elfFile.Section(".note.stapsdt")
	if notes == nil {
		return nil, nil
	}
	if notes.Type != elf.SHT_NOTE {
		return nil, fmt.Errorf("invalid .note.stapsdt section type %s", notes.Type)
	}

	data, err := notes.Data()
	if err != nil {
		return nil, err
	}

	var baseAddr uint64
	if base := elfFile.Section(".stapsdt.base"); base != nil {
		baseAddr = base.Addr
	}

	targets := []usdtTarget{}
	headerSize := binary.Size(sdtHeader{})
	for offset := 0; offset+headerSize <= len(data); {
		header, err := readSDTHeader(elfFile.ByteOrder, data[offset:offset+headerSize])
		if err != nil {
			return nil, err
		}
		namesz := int(header.NameSize)
		descsz := int(header.DescSize)
		offset += headerSize

		nameEnd := offset + namesz
		descStart := offset + align4(namesz)
		descEnd := descStart + descsz
		next := descStart + align4(descsz)
		if namesz <= 0 || descsz <= 0 || nameEnd > len(data) || descEnd > len(data) || next > len(data) {
			return nil, errors.New("malformed .note.stapsdt entry")
		}

		noteName := strings.TrimRight(string(data[offset:nameEnd]), "\x00")
		if header.Type == obiUSDTNoteType && noteName == obiUSDTNoteName {
			note, err := parseUSDTNote(elfFile.Class, elfFile.ByteOrder, data[descStart:descEnd])
			if err != nil {
				return nil, err
			}
			if note.Provider == provider && note.Name == name {
				target, err := usdtTargetFromNote(elfFile, pid, maps, mappedPath, baseAddr, note)
				if err != nil {
					return nil, err
				}
				targets = append(targets, target)
			}
		}
		offset = next
	}

	return targets, nil
}

func usdtTargetFromNote(
	elfFile *elf.File,
	pid app.PID,
	maps []*procfs.ProcMap,
	mappedPath string,
	baseAddr uint64,
	note usdtNote,
) (usdtTarget, error) {
	location, err := adjustedUSDTAddress(baseAddr, note.Base, note.Location)
	if err != nil {
		return usdtTarget{}, err
	}
	relIP, err := elfFileOffset(elfFile, location, true)
	if err != nil {
		return usdtTarget{}, err
	}

	absIP, err := absoluteUSDTIP(pid, maps, mappedPath, relIP)
	if err != nil {
		return usdtTarget{}, err
	}

	var semaOff uint64
	if note.Semaphore != 0 {
		semaphore, err := adjustedUSDTAddress(baseAddr, note.Base, note.Semaphore)
		if err != nil {
			return usdtTarget{}, err
		}
		semaOff, err = elfFileOffset(elfFile, semaphore, false)
		if err != nil {
			return usdtTarget{}, err
		}
	}

	spec, err := parseUSDTArgSpec(elfFile.Machine, note.Args)
	if err != nil {
		return usdtTarget{}, err
	}

	return usdtTarget{
		AbsIP:   absIP,
		RelIP:   relIP,
		SemaOff: semaOff,
		Spec:    spec,
		SpecKey: fmt.Sprintf("%s:%s:%s:%s", elfFile.Machine, note.Provider, note.Name, note.Args),
	}, nil
}

// parsePreResolvedOffset recognizes a probe target given as a file offset
// rather than a symbol name, in the form "0x<hex>".
//
// LOCAL PATCH, not upstream. Offset zero is rejected: it is the ELF header and
// never a probe site, so it is a safe sentinel for "not an offset".
func parsePreResolvedOffset(s string) (uint64, bool) {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return 0, false
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}

// lookupFunctionTarget resolves a function symbol to a uprobe-attachable
// target. Used by custom_span function-mode for symbol-based attachment
// (Go binaries).
func lookupFunctionTarget(
	elfFile *elf.File,
	pid app.PID,
	maps []*procfs.ProcMap,
	mappedPath string,
	function string,
	spec obiUSDTSpec,
) (usdtTarget, error) {
	// LOCAL PATCH, not upstream: accept an already-resolved file offset in
	// place of a symbol name, written as "0x<hex>".
	//
	// Two reasons. A source LINE has no symbol, so a line probe cannot be
	// expressed at all while this only takes names. Resolving a symbol here
	// means parsing the target's symbol table inside the agent, where an
	// incorrect name can fail silently: the probe still reports enabled.
	// A resolved offset can be checked against the target image beforehand.
	//
	// Everything needed is already computed outside by cmd/probe-resolve, which
	// reads .gopclntab (present even under -ldflags="-s -w") and performs the
	// same virtual-address to file-offset conversion elfFileOffset does below.
	//
	// Entry-only by construction: there is no "return" from a line, so this
	// never sets ReturnRelIPs.
	if relIP, ok := parsePreResolvedOffset(function); ok {
		absIP, aerr := absoluteUSDTIP(pid, maps, mappedPath, relIP)
		if aerr != nil {
			return usdtTarget{}, fmt.Errorf("offset %#x: %w", relIP, aerr)
		}
		return usdtTarget{
			AbsIP:   absIP,
			RelIP:   relIP,
			Spec:    spec,
			SpecKey: fmt.Sprintf("%s:off:%x", elfFile.Machine, relIP),
		}, nil
	}

	entryVA, size, err := resolveFunctionSymbol(elfFile, function)
	if err != nil {
		return usdtTarget{}, err
	}

	return functionTargetAt(elfFile, pid, maps, mappedPath, function, spec, entryVA, size)
}

func functionTargetAt(elfFile *elf.File, pid app.PID, maps []*procfs.ProcMap, mappedPath, function string, spec obiUSDTSpec, entryVA, size uint64) (usdtTarget, error) {
	relIP, err := elfFileOffset(elfFile, entryVA, true)
	if err != nil {
		return usdtTarget{}, fmt.Errorf("symbol %q: %w", function, err)
	}
	absIP, err := absoluteUSDTIP(pid, maps, mappedPath, relIP)
	if err != nil {
		return usdtTarget{}, fmt.Errorf("symbol %q: %w", function, err)
	}

	target := usdtTarget{
		AbsIP:   absIP,
		RelIP:   relIP,
		Spec:    spec,
		SpecKey: fmt.Sprintf("%s:func:%s", elfFile.Machine, function),
	}
	// Per-RET uprobes: Go (uretprobe corrupts GC stack) and pre-5.15 (uretprobe
	// IP isn't in the IP map).
	needPerRET := size > 0 && (DetectFunctionLang(elfFile) == FunctionLangGo || !ebpfcommon.HasAttachCookie())
	if needPerRET {
		buf := make([]byte, size)
		if _, err := elfReadFunctionBytes(elfFile, entryVA, buf); err == nil {
			rets, ferr := goexec.FindReturnOffsets(relIP, buf)
			if ferr == nil {
				target.ReturnRelIPs = rets
			}
		}
	}
	if DetectFunctionLang(elfFile) == FunctionLangGo && len(target.ReturnRelIPs) == 0 {
		return usdtTarget{}, fmt.Errorf("go function %q has no resolvable return sites", function)
	}
	return target, nil
}

// resolveFunctionSymbol returns the entry VA + size of a named function.
// Falls back to .gopclntab on stripped Go binaries.
func resolveFunctionSymbol(elfFile *elf.File, function string) (entryVA, size uint64, err error) {
	if va, sz, ok := lookupElfFunctionSym(elfFile, function); ok {
		return va, sz, nil
	}
	if DetectFunctionLang(elfFile) == FunctionLangGo {
		if va, sz, ok := lookupGopclntabFunc(elfFile, function); ok {
			return va, sz, nil
		}
	}
	return 0, 0, fmt.Errorf("symbol %q not found in executable", function)
}

func lookupElfFunctionSym(elfFile *elf.File, function string) (uint64, uint64, bool) {
	syms, _ := elfFile.Symbols()
	dynsyms, _ := elfFile.DynamicSymbols()
	for _, set := range [][]elf.Symbol{syms, dynsyms} {
		for i := range set {
			s := &set[i]
			if s.Name != function || elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value == 0 {
				continue
			}
			return s.Value, s.Size, true
		}
	}
	return 0, 0, false
}

func lookupGopclntabFunc(elfFile *elf.File, function string) (uint64, uint64, bool) {
	// Prefer goexec's moduledata-scanning resolver (matches gotracer). Fall
	// back to the simple .text base when moduledata isn't recoverable —
	// gosym only needs a runtime-text address to decode function entries.
	if tab, err := goexec.GoSymbolTable(elfFile); err == nil && tab != nil {
		if f := tab.LookupFunc(function); f != nil && f.End >= f.Entry {
			return f.Entry, f.End - f.Entry, true
		}
	}
	pcl := elfFile.Section(".gopclntab")
	text := elfFile.Section(".text")
	if pcl == nil || text == nil {
		return 0, 0, false
	}
	data, err := pcl.Data()
	if err != nil {
		return 0, 0, false
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		return 0, 0, false
	}
	f := tab.LookupFunc(function)
	if f == nil || f.End < f.Entry {
		return 0, 0, false
	}
	return f.Entry, f.End - f.Entry, true
}

// elfReadFunctionBytes copies the function's instructions starting at vaddr
// into buf. Returns the number of bytes read on success.
func elfReadFunctionBytes(elfFile *elf.File, vaddr uint64, buf []byte) (int, error) {
	for _, prog := range elfFile.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		if vaddr < prog.Vaddr || vaddr >= prog.Vaddr+prog.Memsz {
			continue
		}
		return prog.ReadAt(buf, int64(vaddr-prog.Vaddr))
	}
	return 0, fmt.Errorf("vaddr %#x not in any executable PT_LOAD segment", vaddr)
}

func adjustedUSDTAddress(baseAddr, noteBase, addr uint64) (uint64, error) {
	if baseAddr == 0 || noteBase == 0 {
		return addr, nil
	}
	if baseAddr >= noteBase {
		delta := baseAddr - noteBase
		if addr > math.MaxUint64-delta {
			return 0, errors.New("USDT address overflow")
		}
		return addr + delta, nil
	}

	delta := noteBase - baseAddr
	if addr < delta {
		return 0, errors.New("USDT address overflow")
	}
	return addr - delta, nil
}

func elfFileOffset(elfFile *elf.File, addr uint64, requireExecutable bool) (uint64, error) {
	for _, prog := range elfFile.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if requireExecutable && prog.Flags&elf.PF_X == 0 {
			continue
		}
		if addr >= prog.Vaddr && addr-prog.Vaddr < prog.Memsz {
			delta := addr - prog.Vaddr
			if prog.Off > math.MaxUint64-delta {
				return 0, errors.New("USDT file offset overflow")
			}
			return delta + prog.Off, nil
		}
	}
	return 0, fmt.Errorf("USDT address %#x is not in a loadable ELF segment", addr)
}

func absoluteUSDTIP(pid app.PID, maps []*procfs.ProcMap, mappedPath string, relIP uint64) (uint64, error) {
	if mappedPath == "" {
		return relIP, nil
	}
	for _, m := range maps {
		if m.Pathname != mappedPath || m.Perms == nil || !m.Perms.Execute {
			continue
		}
		startOffset := uint64(m.Offset)
		size := uint64(m.EndAddr - m.StartAddr)
		if relIP >= startOffset && relIP < startOffset+size {
			return uint64(m.StartAddr) - startOffset + relIP, nil
		}
	}
	return 0, fmt.Errorf("failed to resolve USDT IP %#x for pid %d path %s", relIP, pid, mappedPath)
}

func align4(v int) int {
	if v > math.MaxInt-3 {
		return math.MaxInt
	}
	return (v + 3) &^ 3
}

func parseUSDTArgSpec(machine elf.Machine, args string) (obiUSDTSpec, error) {
	var spec obiUSDTSpec
	remaining := strings.TrimSpace(args)
	for remaining != "" {
		if spec.ArgCount >= obiUSDTMaxArgs {
			return obiUSDTSpec{}, fmt.Errorf("too many USDT arguments: max %d", obiUSDTMaxArgs)
		}

		arg, consumed, err := parseUSDTArg(machine, remaining)
		if err != nil {
			return obiUSDTSpec{}, err
		}
		spec.Args[spec.ArgCount] = arg
		spec.ArgCount++
		remaining = strings.TrimSpace(remaining[consumed:])
	}
	return spec, nil
}

func parseUSDTArg(machine elf.Machine, arg string) (obiUSDTArgSpec, int, error) {
	switch machine {
	case elf.EM_X86_64:
		return parseX86USDTArg(arg)
	case elf.EM_AARCH64:
		return parseArm64USDTArg(arg)
	default:
		return obiUSDTArgSpec{}, 0, fmt.Errorf("%w: %s", errUnsupportedUSDTArch, machine)
	}
}

// regResolver maps an ELF arg's register name (e.g. `%rsi`, `x1`) to its
// byte offset inside `struct pt_regs`.
type regResolver func(string) (int16, error)

func parseX86USDTArg(arg string) (obiUSDTArgSpec, int, error) {
	if m := x86RegDerefArgRE.FindStringSubmatchIndex(arg); m != nil {
		return buildRegDerefArg(arg, m, x86RegisterOffset, 6, 4)
	}
	if m := x86RegArgRE.FindStringSubmatchIndex(arg); m != nil {
		return buildRegArg(arg, m, x86RegisterOffset)
	}
	if m := x86ConstArgRE.FindStringSubmatchIndex(arg); m != nil {
		return buildConstArg(arg, m)
	}
	return obiUSDTArgSpec{}, 0, fmt.Errorf("unrecognized x86_64 USDT argument %q", arg)
}

func parseArm64USDTArg(arg string) (obiUSDTArgSpec, int, error) {
	if m := arm64RegDerefArgRE.FindStringSubmatchIndex(arg); m != nil {
		return buildRegDerefArg(arg, m, arm64RegisterOffset, 4, 6)
	}
	if m := arm64ConstArgRE.FindStringSubmatchIndex(arg); m != nil {
		return buildConstArg(arg, m)
	}
	if m := arm64RegArgRE.FindStringSubmatchIndex(arg); m != nil {
		return buildRegArg(arg, m, arm64RegisterOffset)
	}
	return obiUSDTArgSpec{}, 0, fmt.Errorf("unrecognized arm64 USDT argument %q", arg)
}

// buildRegDerefArg consumes a `<size>@<offset>(%reg)` (x86) or
// `<size>@[reg, offset]` (arm64) capture. `regGroup` and `offGroup` are the
// regexp submatch indices for the register name and the (optional) memory
// offset — the two arches encode them in opposite order.
func buildRegDerefArg(arg string, m []int, resolveReg regResolver, regGroup, offGroup int) (obiUSDTArgSpec, int, error) {
	size, err := parseUSDTArgSize(arg[m[2]:m[3]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	offset, err := parseOptionalInt64(arg, m[offGroup], m[offGroup+1])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	regOff, err := resolveReg(arg[m[regGroup]:m[regGroup+1]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	spec := sizedUSDTArg(size)
	spec.ArgType = obiUSDTArgRegDeref
	spec.ValOff = uint64(offset)
	spec.RegOff = regOff
	return spec, m[1], nil
}

func buildRegArg(arg string, m []int, resolveReg regResolver) (obiUSDTArgSpec, int, error) {
	size, err := parseUSDTArgSize(arg[m[2]:m[3]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	regOff, err := resolveReg(arg[m[4]:m[5]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	spec := sizedUSDTArg(size)
	spec.ArgType = obiUSDTArgReg
	spec.RegOff = regOff
	return spec, m[1], nil
}

func buildConstArg(arg string, m []int) (obiUSDTArgSpec, int, error) {
	size, err := parseUSDTArgSize(arg[m[2]:m[3]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	value, err := strconv.ParseInt(arg[m[4]:m[5]], 0, 64)
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	spec := sizedUSDTArg(size)
	spec.ArgType = obiUSDTArgConst
	spec.ValOff = uint64(value)
	return spec, m[1], nil
}

// parseUSDTArgSize parses the `<width>` field of a stapsdt arg spec. The
// width is signed (negative ⇒ sign-extend on read). Valid magnitudes are
// 1, 2, 4, 8 bytes.
func parseUSDTArgSize(raw string) (int, error) {
	size, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	switch size {
	case 1, 2, 4, 8, -1, -2, -4, -8:
		return size, nil
	}
	return 0, fmt.Errorf("unsupported USDT argument size %d", size)
}

// sizedUSDTArg seeds an arg spec with the bit-shift encoding of `size`
// (negative ⇒ signed). BPF uses the shift to widen sub-64-bit ELF values.
func sizedUSDTArg(size int) obiUSDTArgSpec {
	bytes := size
	signed := uint8(0)
	if bytes < 0 {
		bytes = -bytes
		signed = 1
	}
	return obiUSDTArgSpec{
		ArgSigned:   signed,
		ArgBitshift: uint8(64 - bytes*8),
	}
}

func parseOptionalInt64(src string, start, end int) (int64, error) {
	if start < 0 || end < 0 {
		return 0, nil
	}
	return strconv.ParseInt(src[start:end], 0, 64)
}

// x86RegisterOffsets maps every recognized x86_64 register name (any
// width: r/e/16/8-bit aliases) to its byte offset inside the kernel's
// `struct pt_regs`. Built once at package init so parsing N stapsdt arg
// specs doesn't allocate N copies of the table.
var x86RegisterOffsets = map[string]int16{
	"rip": 128, "eip": 128,
	"rax": 80, "eax": 80, "ax": 80, "al": 80,
	"rbx": 40, "ebx": 40, "bx": 40, "bl": 40,
	"rcx": 88, "ecx": 88, "cx": 88, "cl": 88,
	"rdx": 96, "edx": 96, "dx": 96, "dl": 96,
	"rsi": 104, "esi": 104, "si": 104, "sil": 104,
	"rdi": 112, "edi": 112, "di": 112, "dil": 112,
	"rbp": 32, "ebp": 32, "bp": 32, "bpl": 32,
	"rsp": 152, "esp": 152, "sp": 152, "spl": 152,
	"r8": 72, "r8d": 72, "r8w": 72, "r8b": 72,
	"r9": 64, "r9d": 64, "r9w": 64, "r9b": 64,
	"r10": 56, "r10d": 56, "r10w": 56, "r10b": 56,
	"r11": 48, "r11d": 48, "r11w": 48, "r11b": 48,
	"r12": 24, "r12d": 24, "r12w": 24, "r12b": 24,
	"r13": 16, "r13d": 16, "r13w": 16, "r13b": 16,
	"r14": 8, "r14d": 8, "r14w": 8, "r14b": 8,
	"r15": 0, "r15d": 0, "r15w": 0, "r15b": 0,
}

func x86RegisterOffset(reg string) (int16, error) {
	reg = strings.TrimPrefix(strings.ToLower(reg), "%")
	offset, ok := x86RegisterOffsets[reg]
	if !ok {
		return 0, fmt.Errorf("unsupported x86_64 USDT register %q", reg)
	}
	return offset, nil
}

func arm64RegisterOffset(reg string) (int16, error) {
	reg = strings.ToLower(reg)
	if reg == "sp" {
		return 248, nil
	}
	if len(reg) < 2 || (reg[0] != 'x' && reg[0] != 'w') {
		return 0, fmt.Errorf("unsupported arm64 USDT register %q", reg)
	}
	num, err := strconv.Atoi(reg[1:])
	if err != nil || num < 0 || num >= 31 {
		return 0, fmt.Errorf("unsupported arm64 USDT register %q", reg)
	}
	return int16(num * 8), nil
}
