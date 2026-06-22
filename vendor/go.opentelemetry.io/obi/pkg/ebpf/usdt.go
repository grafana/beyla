// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

const (
	obiUSDTMaxArgs     = 12
	obiUSDTMaxSpecCnt  = 256
	obiUSDTNoteType    = 3
	obiUSDTNoteName    = "stapsdt"
	obiUSDTArgConst    = uint8(0)
	obiUSDTArgReg      = uint8(1)
	obiUSDTArgRegDeref = uint8(2)
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

type obiUSDTSpec struct {
	Args     [obiUSDTMaxArgs]obiUSDTArgSpec
	Cookie   uint64
	ArgCount uint16
	_        [6]byte
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
	location := adjustedUSDTAddress(baseAddr, note.Base, note.Location)
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
		semaphore := adjustedUSDTAddress(baseAddr, note.Base, note.Semaphore)
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

func adjustedUSDTAddress(baseAddr, noteBase, addr uint64) uint64 {
	if baseAddr == 0 || noteBase == 0 {
		return addr
	}
	return addr + baseAddr - noteBase
}

func elfFileOffset(elfFile *elf.File, addr uint64, requireExecutable bool) (uint64, error) {
	for _, prog := range elfFile.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if requireExecutable && prog.Flags&elf.PF_X == 0 {
			continue
		}
		if addr >= prog.Vaddr && addr < prog.Vaddr+prog.Memsz {
			return addr - prog.Vaddr + prog.Off, nil
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

func parseX86USDTArg(arg string) (obiUSDTArgSpec, int, error) {
	if match := x86RegDerefArgRE.FindStringSubmatchIndex(arg); match != nil {
		return buildX86RegDerefArg(arg, match)
	}
	if match := x86RegArgRE.FindStringSubmatchIndex(arg); match != nil {
		return buildX86RegArg(arg, match)
	}
	if match := x86ConstArgRE.FindStringSubmatchIndex(arg); match != nil {
		return buildConstArg(arg, match)
	}
	return obiUSDTArgSpec{}, 0, fmt.Errorf("unrecognized x86_64 USDT argument %q", arg)
}

func parseArm64USDTArg(arg string) (obiUSDTArgSpec, int, error) {
	if match := arm64RegDerefArgRE.FindStringSubmatchIndex(arg); match != nil {
		return buildArm64RegDerefArg(arg, match)
	}
	if match := arm64ConstArgRE.FindStringSubmatchIndex(arg); match != nil {
		return buildConstArg(arg, match)
	}
	if match := arm64RegArgRE.FindStringSubmatchIndex(arg); match != nil {
		return buildArm64RegArg(arg, match)
	}
	return obiUSDTArgSpec{}, 0, fmt.Errorf("unrecognized arm64 USDT argument %q", arg)
}

func buildX86RegDerefArg(arg string, match []int) (obiUSDTArgSpec, int, error) {
	size, err := parseUSDTArgSize(arg[match[2]:match[3]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	offset, err := parseOptionalInt64(arg, match[4], match[5])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	regOff, err := x86RegisterOffset(arg[match[6]:match[7]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}

	spec := sizedUSDTArg(size)
	spec.ArgType = obiUSDTArgRegDeref
	spec.ValOff = uint64(offset)
	spec.RegOff = regOff
	return spec, match[1], nil
}

func buildX86RegArg(arg string, match []int) (obiUSDTArgSpec, int, error) {
	size, err := parseUSDTArgSize(arg[match[2]:match[3]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	regOff, err := x86RegisterOffset(arg[match[4]:match[5]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}

	spec := sizedUSDTArg(size)
	spec.ArgType = obiUSDTArgReg
	spec.RegOff = regOff
	return spec, match[1], nil
}

func buildArm64RegDerefArg(arg string, match []int) (obiUSDTArgSpec, int, error) {
	size, err := parseUSDTArgSize(arg[match[2]:match[3]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	regOff, err := arm64RegisterOffset(arg[match[4]:match[5]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	offset, err := parseOptionalInt64(arg, match[6], match[7])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}

	spec := sizedUSDTArg(size)
	spec.ArgType = obiUSDTArgRegDeref
	spec.ValOff = uint64(offset)
	spec.RegOff = regOff
	return spec, match[1], nil
}

func buildArm64RegArg(arg string, match []int) (obiUSDTArgSpec, int, error) {
	size, err := parseUSDTArgSize(arg[match[2]:match[3]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	regOff, err := arm64RegisterOffset(arg[match[4]:match[5]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}

	spec := sizedUSDTArg(size)
	spec.ArgType = obiUSDTArgReg
	spec.RegOff = regOff
	return spec, match[1], nil
}

func buildConstArg(arg string, match []int) (obiUSDTArgSpec, int, error) {
	size, err := parseUSDTArgSize(arg[match[2]:match[3]])
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}
	value, err := strconv.ParseInt(arg[match[4]:match[5]], 0, 64)
	if err != nil {
		return obiUSDTArgSpec{}, 0, err
	}

	spec := sizedUSDTArg(size)
	spec.ArgType = obiUSDTArgConst
	spec.ValOff = uint64(value)
	return spec, match[1], nil
}

func parseUSDTArgSize(raw string) (int, error) {
	size, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	absSize := size
	if absSize < 0 {
		absSize = -absSize
	}
	switch absSize {
	case 1, 2, 4, 8:
		return size, nil
	default:
		return 0, fmt.Errorf("unsupported USDT argument size %d", size)
	}
}

func sizedUSDTArg(size int) obiUSDTArgSpec {
	if size < 0 {
		return obiUSDTArgSpec{
			ArgSigned:   1,
			ArgBitshift: uint8(64 - (-size * 8)),
		}
	}
	return obiUSDTArgSpec{ArgBitshift: uint8(64 - (size * 8))}
}

func parseOptionalInt64(src string, start, end int) (int64, error) {
	if start < 0 || end < 0 {
		return 0, nil
	}
	return strconv.ParseInt(src[start:end], 0, 64)
}

func x86RegisterOffset(reg string) (int16, error) {
	reg = strings.TrimPrefix(strings.ToLower(reg), "%")
	offsets := map[string]int16{
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
	offset, ok := offsets[reg]
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
