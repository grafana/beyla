// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/grafana/go-offsets-tracker/pkg/offsets"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// shtRELR is the ELF section type for compact relative relocations (SHT_RELR = 19).
// Not yet defined in Go's debug/elf package.
const shtRELR = elf.SectionType(19)

// relocationInfo holds the two kinds of relative relocations we decode from an ELF binary.
//
// RELA relocations carry an explicit addend in the relocation entry itself; the dynamic
// linker writes that addend as the pointer value at r_offset. We record it as a map from
// target address to the resolved value.
//
// RELR relocations are compact relative relocations. They only tell us which addresses will
// be relocated; the actual value is the word already stored at that address in the file
// (which the dynamic linker adds load_base to). We record just the set of target addresses.
type relocationInfo struct {
	explicit map[uint64]uint64   // RELA: target address -> resolved value (r_addend)
	relr     map[uint64]struct{} // RELR: target addresses (value is at the address on disk)
}

// moduledataOffsets holds virtual-address offsets for the runtime.moduledata fields we read.
type moduledataOffsets struct {
	pcHeader  uint64
	pclntable uint64 // offset of pclntable.data (slice header start)
	minpc     uint64
	maxpc     uint64
	text      uint64
	etext     uint64
}

func isSupportedGoBinary(elfF *elf.File) error {
	goVersion, _, err := getGoDetails(elfF)
	if err == nil && !supportedGoVersion(goVersion) {
		return fmt.Errorf("unsupported Go version: %v. Minimum supported version is %v", goVersion, minGoVersion)
	}
	return nil
}

// instrumentationPoints loads the provided executable and looks for the addresses
// where the start and return probes must be inserted.
func instrumentationPoints(elfF *elf.File, funcNames []string) (map[string]FuncOffsets, error) {
	ilog := slog.With("component", "goexec.instructions")
	ilog.Debug("searching for instrumentation points", "functions", funcNames)
	functions := map[string]struct{}{}
	for _, fn := range funcNames {
		functions[fn] = struct{}{}
	}

	symTab, err := findGoSymbolTable(elfF)
	if err != nil {
		return nil, err
	}

	if err = isSupportedGoBinary(elfF); err != nil {
		return nil, err
	}

	gosyms := elfF.Section(".gosymtab")

	var allSyms map[string]procs.Sym

	// no go symbols in the executable, maybe it's statically linked
	// find regular elf symbols
	if gosyms == nil {
		allSyms, _ = procs.FindExeSymbols(elfF, funcNames)
	}

	allOffsets := map[string]FuncOffsets{}
	for _, f := range symTab.Funcs {
		fName := f.Name
		// fetch short path of function for vendor scene
		if paths := strings.Split(fName, "/vendor/"); len(paths) > 1 {
			fName = paths[1]
		}

		if _, ok := functions[fName]; ok {
			// when we don't have a Go symbol table, the executable is statically linked, we don't look for offsets
			// using the gosym tab, we lookup offsets just like a regular elf file.
			// we still need to find the return statements, since go linkage is non-standard we can't use uretprobe
			if gosyms == nil && len(allSyms) > 0 {
				handleStaticSymbol(fName, allOffsets, allSyms, ilog)
				continue
			}

			offs, ok, err := findFuncOffset(&f, elfF)
			if err != nil {
				return nil, err
			}
			if ok {
				ilog.Debug("found relevant function for instrumentation", "function", fName, "offsets", offs)
				allOffsets[fName] = offs
			}
		}
	}

	return allOffsets, nil
}

func handleStaticSymbol(fName string, allOffsets map[string]FuncOffsets, allSyms map[string]procs.Sym, ilog *slog.Logger) {
	s, ok := allSyms[fName]

	if ok && s.Prog != nil {
		data := make([]byte, s.Len)
		_, err := s.Prog.ReadAt(data, int64(s.Off-s.Prog.Off))
		if err != nil {
			ilog.Error("error reading instructions for symbol", "symbol", fName, "error", err)
			return
		}

		returns, err := FindReturnOffsets(s.Off, data)
		if err != nil {
			ilog.Error("error finding returns for symbol", "symbol", fName, "offset", s.Off-s.Prog.Off, "size", s.Len, "error", err)
			return
		}
		allOffsets[fName] = FuncOffsets{Start: s.Off, Returns: returns}
	} else {
		ilog.Debug("can't find in elf symbol table", "symbol", fName, "ok", ok, "prog", s.Prog)
	}
}

// findFuncOffset gets the start address and end addresses of the function whose symbol is passed
func findFuncOffset(f *gosym.Func, elfF *elf.File) (FuncOffsets, bool, error) {
	for _, prog := range elfF.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		// For more info on this calculation: stackoverflow.com/a/40249502
		if prog.Vaddr <= f.Value && f.Value < (prog.Vaddr+prog.Memsz) {
			off := f.Value - prog.Vaddr + prog.Off

			if f.End < f.Entry {
				continue
			}
			funcLen := f.End - f.Entry
			if funcLen == 0 {
				continue
			}
			data := make([]byte, funcLen)
			_, err := prog.ReadAt(data, int64(f.Value-prog.Vaddr))
			if err != nil {
				return FuncOffsets{}, false, fmt.Errorf("finding function return: %w", err)
			}

			returns, err := FindReturnOffsets(off, data)
			if err != nil {
				return FuncOffsets{}, false, fmt.Errorf("finding function return: %w", err)
			}
			return FuncOffsets{Start: off, Returns: returns}, true, nil
		}
	}

	return FuncOffsets{}, false, nil
}

func findGoSymbolTable(elfF *elf.File) (*gosym.Table, error) {
	var err error
	var pclndat []byte
	gopclntab := elfF.Section(".gopclntab")
	if gopclntab != nil {
		if pclndat, err = gopclntab.Data(); err != nil {
			return nil, fmt.Errorf("acquiring .gopclntab data: %w", err)
		}
	}

	runtimeText, err := findRuntimeText(elfF, gopclntab, pclndat)
	if err != nil {
		return nil, fmt.Errorf("finding runtime text base: %w", err)
	}

	pcln := gosym.NewLineTable(pclndat, runtimeText)
	// First argument accepts the .gosymtab ELF section.
	// Since Go 1.3, .gosymtab is empty so we just pass a nil slice.
	symTab, err := gosym.NewTable(nil, pcln)
	if err != nil {
		return nil, fmt.Errorf("creating go symbol table: %w", err)
	}
	return symTab, nil
}

// findRuntimeText locates the base virtual address of the Go runtime's .text section.
// Historically (up to go 1.25), this was done by reading the textStart field from the
// pcHeader struct embedded in .gopclntab. However, this field was removed, as the following
// comment in the Go source code explains:
//
//	type pcHeader struct {
//		  magic      abi.PCLnTabMagic // abi.Go1NNPcLnTabMagic
//		  pad1, pad2 uint8            // 0,0
//		  minLC      uint8            // min instruction size
//		  ptrSize    uint8            // size of a ptr in bytes
//		  nfunc      int              // number of functions in the module
//		  nfiles     uint             // number of entries in the file tab
//
//		  // The next field used to be textStart. This is no longer stored
//		  // as it requires a relocation. Code should use the moduledata text
//		  // field instead. This unused field can be removed in coordination
//		  // with Delve.
//		  _ uintptr
//
//		  funcnameOffset uintptr // offset to the funcnametab variable from pcHeader
//		  cuOffset       uintptr // offset to the cutab variable from pcHeader
//		  filetabOffset  uintptr // offset to the filetab variable from pcHeader
//		  pctabOffset    uintptr // offset to the pctab variable from pcHeader
//		  pclnOffset     uintptr // offset to the pclntab variable from pcHeader
//	}
//
// Therefore we try to extract it from the moduledata struct, falling back to
// the legacy pcHeader path only when the scan fails.
func findRuntimeText(elfF *elf.File, gopclntab *elf.Section, pclndat []byte) (uint64, error) {
	ilog := slog.With("component", "goexec.instructions")

	rt, modErr := findRuntimeTextFromModuledata(elfF, gopclntab)

	if modErr == nil {
		ilog.Debug("runtimeText resolved from moduledata", "addr", fmt.Sprintf("0x%x", rt))
		return rt, nil
	}

	rt, pclnErr := findRuntimeTextFromPclntab(pclndat)

	if pclnErr == nil {
		ilog.Warn("runtimeText resolved from legacy pclntab path", "addr", fmt.Sprintf("0x%x", rt))
		return rt, nil
	}

	return 0, fmt.Errorf("unable to determine runtime text base: moduledata: %w; pclntab: %w", modErr, pclnErr)
}

// findRuntimeTextFromModuledata tries to heuristically locate runtime.moduledata (since there's no symbol
// or fixed address) by looking for something that looks like a valid moduledata struct:
//
//	type moduledata struct {
//	    pcHeader  *pcHeader        // -> start of .gopclntab
//	    /* ... */
//	    pclntable []byte           // slice; data pointer -> within .gopclntab
//	    /* ... */
//	    minpc, maxpc uintptr       // overall PC range [minpc, maxpc)
//	    text, etext  uintptr       // Go text region [text, etext)
//	    /* ... */
//	}
//
// Since we know the address of .gopclntab, we look for 8-byte words in the binary that point
// to it, then check whether the surrounding data matches the expected moduledata layout.
//
// Note: pcHeader points to the exact start of .gopclntab. pclntable.data points into .gopclntab
// at the function-table offset (not necessarily the start), so we validate it as a range check.
func findRuntimeTextFromModuledata(elfF *elf.File, gopclntab *elf.Section) (uint64, error) {
	if elfF.Class != elf.ELFCLASS64 {
		return 0, errors.New("moduledata scan only implemented for 64-bit ELF")
	}

	if gopclntab == nil {
		return 0, errors.New("no .gopclntab section")
	}

	mdoffs, err := loadModuledataOffsets(elfF)
	if err != nil {
		return 0, err
	}

	relocs := buildRelocationInfo(elfF)

	candidates := moduledataCandidates(elfF, gopclntab.Addr, mdoffs, relocs)

	ilog := slog.With("component", "goexec.instructions")

	for _, candidate := range candidates {
		if !inWritableSection(elfF, candidate) {
			continue
		}

		if text, ok := validateModuledata(elfF, candidate, gopclntab.Addr, gopclntab.Size, mdoffs, relocs); ok {
			ilog.Debug("moduledata found", "candidate", fmt.Sprintf("0x%x", candidate), "text", fmt.Sprintf("0x%x", text))
			return text, nil
		}
	}

	ilog.Debug("moduledata not found", "candidates", len(candidates))

	return 0, errors.New("runtime.moduledata not found")
}

func loadModuledataOffsets(elfF *elf.File) (moduledataOffsets, error) {
	goVersion, _, err := getGoDetails(elfF)
	if err != nil {
		return moduledataOffsets{}, fmt.Errorf("getting Go version: %w", err)
	}

	goVersion = strings.ReplaceAll(goVersion, "go", "")

	offs, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	if err != nil {
		return moduledataOffsets{}, fmt.Errorf("reading prefetched offsets: %w", err)
	}

	var md moduledataOffsets

	fields := []struct {
		name string
		dest *uint64
	}{
		{"pcHeader", &md.pcHeader},
		{"pclntable", &md.pclntable},
		{"minpc", &md.minpc},
		{"maxpc", &md.maxpc},
		{"text", &md.text},
		{"etext", &md.etext},
	}

	for _, f := range fields {
		var ok bool
		if *f.dest, ok = offs.Find("runtime.moduledata", f.name, goVersion); !ok {
			return moduledataOffsets{},
				fmt.Errorf("missing runtime.moduledata.%s offset for Go %s", f.name, goVersion)
		}
	}

	return md, nil
}

// findRuntimeTextFromPclntab reads the textStart field from the pcHeader embedded in pclntab.
// This is a legacy fallback only. Since Go 1.26 the field is gone (renamed to _ uintptr),
// so this path is fundamentally unreliable and should never be reached on modern binaries.
func findRuntimeTextFromPclntab(pclndat []byte) (uint64, error) {
	if len(pclndat) <= 8*2*8 {
		return 0, errors.New("pclntab too short to contain textStart")
	}

	ptrSize := uint32(pclndat[7])

	var rt uint64

	switch ptrSize {
	case 4:
		rt = uint64(binary.LittleEndian.Uint32(pclndat[8+2*ptrSize:]))
	case 8:
		rt = binary.LittleEndian.Uint64(pclndat[8+2*ptrSize:])
	default:
		return 0, fmt.Errorf("unknown pclntab pointer size: %d", ptrSize)
	}

	if rt == 0 {
		return 0, errors.New("textStart is zero (field removed in Go 1.26+)")
	}

	return rt, nil
}

// moduledataCandidates returns candidate virtual addresses for runtime.firstmoduledata using
// four strategies: ELF symbol table, RELA entries, RELR entries, and a direct section scan.
func moduledataCandidates(elfF *elf.File, gopclntabAddr uint64, mdoffs moduledataOffsets, relocs relocationInfo) []uint64 {
	seen := map[uint64]struct{}{}
	var candidates []uint64

	add := func(addr uint64) {
		if _, ok := seen[addr]; !ok {
			seen[addr] = struct{}{}
			candidates = append(candidates, addr)
		}
	}

	// tryPointerField derives candidate moduledata base addresses from a virtual address
	// that holds a pointer somewhere in .gopclntab. Both pcHeader (exact start) and
	// pclntable.data (internal offset) point there, so each match yields two candidates.
	tryPointerField := func(vaddr uint64) {
		if vaddr >= mdoffs.pcHeader {
			add(vaddr - mdoffs.pcHeader)
		}
		if vaddr >= mdoffs.pclntable {
			add(vaddr - mdoffs.pclntable)
		}
	}

	// Strategy 1: symbol table (non-stripped binaries).
	syms, _ := elfF.Symbols()
	for _, sym := range syms {
		if sym.Name == "runtime.firstmoduledata" {
			add(sym.Value)
		}
	}

	// Strategy 2: RELA entries (CGo PIE binaries).
	// Pointer fields are zero on disk; the dynamic linker stores their values as explicit addends.
	for vaddr, addend := range relocs.explicit {
		if addend == gopclntabAddr {
			tryPointerField(vaddr)
		}
	}

	// Strategy 3: RELR entries (PIE binaries with compact relative relocations).
	// Every RELR target holds a relocated pointer by definition — no pre-filtering needed.
	// validateModuledata enforces all structural checks and will reject false positives.
	for vaddr := range relocs.relr {
		tryPointerField(vaddr)
	}

	// Strategy 4: direct section scan (pure-Go and static binaries where pointers are stored
	// as absolute virtual addresses rather than relocatable addends).
	for _, sec := range elfF.Sections {
		if sec.Type == elf.SHT_NOBITS || sec.Type == elf.SHT_NULL || sec.Flags&elf.SHF_WRITE == 0 {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for i := 0; i+8 <= len(data); i += 8 {
			if elfF.ByteOrder.Uint64(data[i:]) != gopclntabAddr {
				continue
			}
			tryPointerField(sec.Addr + uint64(i))
		}
	}

	return candidates
}

// validateModuledata checks that a candidate virtual address is a valid runtime.moduledata.
//
// Checks applied (all must pass):
//  1. pclntable.data lies within .gopclntab — it points to the function-table slice inside
//     the pclntab, not necessarily to its start.
//  2. pcHeader == gopclntabAddr — pcHeader is a *pcHeader at the exact start of .gopclntab.
//  3. text is non-zero, less than etext, within [minpc, maxpc), and in an executable segment.
//
// Returns the text field value and true on success.
func validateModuledata(elfF *elf.File, candidate, gopclntabAddr, gopclntabSize uint64, mdoffs moduledataOffsets, relocs relocationInfo) (uint64, bool) {
	// pclntable.data must be within [gopclntabAddr, gopclntabAddr+gopclntabSize).
	pclntableData := resolveAddr(elfF, candidate+mdoffs.pclntable, relocs)
	if pclntableData < gopclntabAddr || pclntableData >= gopclntabAddr+gopclntabSize {
		return 0, false
	}

	// pcHeader must point to the exact start of .gopclntab.
	if resolveAddr(elfF, candidate+mdoffs.pcHeader, relocs) != gopclntabAddr {
		return 0, false
	}

	text := resolveAddr(elfF, candidate+mdoffs.text, relocs)
	if text == 0 {
		return 0, false
	}

	etext := resolveAddr(elfF, candidate+mdoffs.etext, relocs)
	if etext == 0 || text >= etext {
		return 0, false
	}

	minpc := resolveAddr(elfF, candidate+mdoffs.minpc, relocs)
	maxpc := resolveAddr(elfF, candidate+mdoffs.maxpc, relocs)
	if text < minpc || text >= maxpc {
		return 0, false
	}

	if !inExecutableSegment(elfF, text) || !inExecutableSegment(elfF, etext-1) {
		return 0, false
	}

	return text, true
}

// resolveAddr returns the pointer value stored at vaddr, preferring the explicit RELA addend
// when one is present, otherwise reading the word directly from the file.
// For RELR targets the stored word on disk is already the link-time virtual address
// (load_base == 0 for zero-based PIE), so reading the file gives the correct value.
func resolveAddr(elfF *elf.File, vaddr uint64, relocs relocationInfo) uint64 {
	if addend, ok := relocs.explicit[vaddr]; ok {
		return addend
	}
	return readAddr(elfF, vaddr)
}

// readAddr reads a 64-bit word from the ELF section containing the given virtual address.
func readAddr(elfF *elf.File, vaddr uint64) uint64 {
	for _, prog := range elfF.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if vaddr < prog.Vaddr || vaddr+8 > prog.Vaddr+prog.Memsz {
			continue
		}
		data := make([]byte, 8)
		if _, err := prog.ReadAt(data, int64(vaddr-prog.Vaddr)); err != nil {
			return 0
		}
		return elfF.ByteOrder.Uint64(data)
	}
	return 0
}

// inWritableSection reports whether addr falls within a writable ELF section.
// Used to reject bogus moduledata candidates before running full validation.
func inWritableSection(elfF *elf.File, addr uint64) bool {
	for _, sec := range elfF.Sections {
		if sec.Flags&elf.SHF_WRITE == 0 {
			continue
		}
		if addr >= sec.Addr && addr < sec.Addr+sec.Size {
			return true
		}
	}
	return false
}

// inExecutableSegment reports whether addr falls within an executable PT_LOAD segment.
func inExecutableSegment(elfF *elf.File, addr uint64) bool {
	for _, prog := range elfF.Progs {
		if prog.Type == elf.PT_LOAD && prog.Flags&elf.PF_X != 0 {
			if addr >= prog.Vaddr && addr < prog.Vaddr+prog.Memsz {
				return true
			}
		}
	}
	return false
}

func relativeRelocationType(m elf.Machine) (uint32, bool) {
	switch m {
	case elf.EM_X86_64:
		return uint32(elf.R_X86_64_RELATIVE), true
	case elf.EM_AARCH64:
		return uint32(elf.R_AARCH64_RELATIVE), true
	default:
		return 0, false
	}
}

// buildRelocationInfo decodes both SHT_RELA and SHT_RELR sections into a relocationInfo.
// Only x86-64 and arm64 are supported; other architectures return an empty result.
func buildRelocationInfo(elfF *elf.File) relocationInfo {
	relocs := relocationInfo{
		explicit: map[uint64]uint64{},
		relr:     map[uint64]struct{}{},
	}

	relativeType, ok := relativeRelocationType(elfF.Machine)
	if !ok {
		return relocs
	}

	for _, sec := range elfF.Sections {
		switch sec.Type {
		case elf.SHT_RELA:
			if data, err := sec.Data(); err == nil {
				decodeRelaRelative(relocs.explicit, data, elfF.ByteOrder, relativeType)
			}
		case shtRELR:
			if data, err := sec.Data(); err == nil {
				decodeRelr(relocs.relr, data, elfF.ByteOrder)
			}
		}
	}

	return relocs
}

// decodeRelaRelative decodes SHT_RELA entries, recording only R_*_RELATIVE ones.
// For each matching entry it records r_offset -> r_addend (the explicit pointer value
// the dynamic linker will write at that address).
func decodeRelaRelative(explicit map[uint64]uint64, data []byte, order binary.ByteOrder, relativeType uint32) {
	r := bytes.NewReader(data)

	for {
		var entry struct {
			Offset uint64
			Info   uint64
			Addend int64
		}

		if err := binary.Read(r, order, &entry); err != nil {
			break
		}

		if uint32(entry.Info) == relativeType && entry.Addend >= 0 {
			explicit[entry.Offset] = uint64(entry.Addend)
		}
	}
}

// decodeRelr decodes a SHT_RELR section, recording the virtual address of every
// relocated word into the relr set.
//
// RELR is a compact encoding where each 8-byte word is either:
//   - an explicit relocated address (LSB = 0): one word at that address is relocated;
//     base advances to address+8.
//   - a bitmap (LSB = 1): bits [1..63] select which of the next 63 word slots after
//     the current base are relocated; base advances by 63 words (504 bytes).
//
// Unlike RELA, RELR carries no explicit value. The dynamic linker adds load_base to
// the word already stored at the target address. resolveAddr handles this by reading
// the word from the file directly when it sees a RELR target.
func decodeRelr(relr map[uint64]struct{}, data []byte, order binary.ByteOrder) {
	const wordSize = uint64(8)

	r := bytes.NewReader(data)
	var base uint64

	for {
		var word uint64
		if err := binary.Read(r, order, &word); err != nil {
			break
		}

		if word&1 == 0 {
			// Explicit relocated address.
			base = word
			relr[base] = struct{}{}
			base += wordSize
		} else {
			// Bitmap entry: bits [1..63] select word slots after base.
			bitmap := word >> 1
			for b := 0; b < 63; b++ {
				if bitmap&(1<<uint(b)) != 0 {
					relr[base+wordSize*uint64(b)] = struct{}{}
				}
			}
			base += wordSize * 63
		}
	}
}
