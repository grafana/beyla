// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"strings"

	"go.opentelemetry.io/obi/internal/goabi"
	"go.opentelemetry.io/obi/internal/goversion"
)

const (
	prefixNew        = "go:itab."
	prefixOld        = "go.itab."
	prefixLen        = len(prefixNew)
	maxGoTypeNameLen = 4096
)

func isITabEntry(sym string) bool {
	return strings.Contains(sym, prefixNew) || strings.Contains(sym, prefixOld)
}

func iTabType(sym string) string {
	if len(sym) <= prefixLen {
		return ""
	}
	parts := strings.Split(sym[prefixLen:], ",")
	if len(parts) < 2 {
		return ""
	}

	return parts[0]
}

func findInterfaceImpls(ef *elf.File) (map[string]uint64, error) {
	implementations := map[string]uint64{}
	symbols, err := ef.Symbols()
	if err != nil {
		if !errors.Is(err, elf.ErrNoSymbols) {
			return nil, fmt.Errorf("accessing symbols table: %w", err)
		}
	}
	for _, s := range symbols {
		// Name is in format: go:itab.*net/http.response,net/http.ResponseWriter or go.itab.*net/http.response,net/http.ResponseWriter on old versions
		if !isITabEntry(s.Name) {
			continue
		}
		iType := iTabType(s.Name)
		if iType != "" {
			implementations[iType] = s.Value
		}
	}

	versionString, _, err := getGoDetails(ef)
	if err != nil {
		return implementations, nil
	}
	targetVersion, err := goversion.Parse(versionString)
	if err != nil || targetVersion.Compare(minGoRuntimeTypeMetadataVersion) < 0 {
		return implementations, nil
	}

	moduleImplementations, err := findInterfaceImplsFromModuledata(ef, targetVersion)
	if err != nil {
		return nil, err
	}
	maps.Copy(implementations, moduleImplementations)
	return implementations, nil
}

func findInterfaceImplsFromModuledata(ef *elf.File, targetVersion goversion.Version) (map[string]uint64, error) {
	if ef.Class != elf.ELFCLASS64 {
		return nil, errors.New("go runtime metadata discovery only supports 64-bit ELF")
	}

	gopclntab := ef.Section(".gopclntab")
	if gopclntab == nil {
		return nil, errors.New("no .gopclntab section")
	}

	runtimeABI, err := loadGoRuntimeABI(ef, targetVersion)
	if err != nil {
		return nil, err
	}
	mdoffs := runtimeABI.Moduledata
	metadata := runtimeABI.TypeMetadata
	if metadata == nil {
		return nil, errors.New("go runtime type metadata ABI is unavailable")
	}
	relocs := buildRelocationInfo(ef)
	for _, candidate := range moduledataCandidates(ef, gopclntab.Addr, mdoffs, relocs) {
		if !inWritableSection(ef, candidate) {
			continue
		}
		if _, ok := validateModuledata(ef, candidate, gopclntab.Addr, gopclntab.Size, mdoffs, relocs); !ok {
			continue
		}

		return readGoInterfaceImpls(ef, candidate, mdoffs, metadata, relocs)
	}

	return nil, errors.New("runtime.moduledata not found")
}

func readGoInterfaceImpls(
	ef *elf.File,
	moduledata uint64,
	mdoffs goabi.Moduledata,
	abi *goabi.TypeMetadata,
	relocs relocationInfo,
) (map[string]uint64, error) {
	types := resolveAddr(ef, moduledata+mdoffs.Types, relocs)
	typeDescLen := readAddr(ef, moduledata+mdoffs.TypeDescLen)
	itabOffset := readAddr(ef, moduledata+mdoffs.ITabOffset)
	itabSize := readAddr(ef, moduledata+mdoffs.ITabSize)
	if types == 0 || typeDescLen == 0 || itabOffset < typeDescLen || itabSize == 0 {
		return nil, errors.New("invalid Go runtime type metadata")
	}
	if itabOffset > ^uint64(0)-types || itabSize > ^uint64(0)-(types+itabOffset) {
		return nil, errors.New("go itab metadata overflows address space")
	}

	implementations := map[string]uint64{}
	itabAddr := types + itabOffset
	itabEnd := itabAddr + itabSize
	itabFuncEntrySize := abi.ITabFuncEntrySize()
	for itabAddr < itabEnd {
		if itabEnd-itabAddr < abi.ITabBaseSize {
			return nil, errors.New("truncated Go itab metadata")
		}

		interfaceType := resolveAddr(ef, itabAddr+abi.ITabInterOffset, relocs)
		concreteType := resolveAddr(ef, itabAddr+abi.ITabTypeOffset, relocs)
		firstMethod := resolveAddr(ef, itabAddr+abi.ITabFunOffset, relocs)
		if interfaceType == 0 || concreteType < types || concreteType >= types+itabOffset {
			return nil, errors.New("invalid Go itab entry")
		}

		typeName, err := goTypeName(ef, types, concreteType, abi)
		if err != nil {
			return nil, err
		}
		if typeName != "" {
			implementations[typeName] = itabAddr
		}

		itabEntrySize := abi.ITabBaseSize
		if firstMethod != 0 {
			methodCount := readAddr(ef, interfaceType+abi.InterfaceMethodCountOffset())
			if methodCount == 0 ||
				methodCount-1 > (itabEnd-itabAddr-itabEntrySize)/itabFuncEntrySize {
				return nil, errors.New("invalid Go itab method count")
			}
			itabEntrySize += (methodCount - 1) * itabFuncEntrySize
		}
		itabAddr += itabEntrySize
	}

	return implementations, nil
}

func goTypeName(ef *elf.File, types, typeAddr uint64, abi *goabi.TypeMetadata) (string, error) {
	typeHeader, err := readVirtualMemory(ef, typeAddr, abi.TypeHeaderSize())
	if err != nil {
		return "", fmt.Errorf("reading Go type descriptor: %w", err)
	}

	nameOffset := int32(ef.ByteOrder.Uint32(typeHeader[abi.TypeNameOffset:]))
	if nameOffset < 0 || uint64(nameOffset) > ^uint64(0)-types {
		return "", errors.New("invalid Go type name offset")
	}
	name, err := goTypeMetadataName(ef, types, nameOffset)
	if err != nil {
		return "", fmt.Errorf("reading Go type name: %w", err)
	}
	if typeHeader[abi.TypeTFlagOffset]&byte(abi.TFlagExtraStarMask) != 0 {
		name = strings.TrimPrefix(name, "*")
	}

	pkgPath, err := goTypePackagePath(ef, types, typeAddr, typeHeader, abi)
	if err != nil {
		return "", err
	}
	if pkgPath != "" {
		pointerPrefix := ""
		shortName := name
		if strings.HasPrefix(shortName, "*") {
			pointerPrefix = "*"
			shortName = strings.TrimPrefix(shortName, "*")
		}
		if dot := strings.IndexByte(shortName, '.'); dot >= 0 {
			shortName = shortName[dot+1:]
		}
		name = pointerPrefix + pkgPath + "." + shortName
	}
	return name, nil
}

func goTypePackagePath(
	ef *elf.File,
	types, typeAddr uint64,
	typeHeader []byte,
	abi *goabi.TypeMetadata,
) (string, error) {
	if typeHeader[abi.TypeTFlagOffset]&byte(abi.TFlagUncommonMask) == 0 {
		return "", nil
	}

	uncommonOffset := abi.UncommonTypeOffset(typeHeader[abi.TypeKindOffset])
	pkgPathBytes, err := readVirtualMemory(
		ef,
		typeAddr+uncommonOffset+abi.UncommonPkgPathOffset,
		abi.NameOffsetSize,
	)
	if err != nil {
		return "", fmt.Errorf("reading Go type package path offset: %w", err)
	}
	pkgPathOffset := int32(ef.ByteOrder.Uint32(pkgPathBytes))
	if pkgPathOffset == 0 {
		return "", nil
	}
	pkgPath, err := goTypeMetadataName(ef, types, pkgPathOffset)
	if err != nil {
		return "", fmt.Errorf("reading Go type package path: %w", err)
	}
	return pkgPath, nil
}

func goTypeMetadataName(ef *elf.File, types uint64, nameOffset int32) (string, error) {
	if nameOffset < 0 || uint64(nameOffset) > ^uint64(0)-types {
		return "", errors.New("invalid Go name offset")
	}
	nameAddr := types + uint64(nameOffset)
	nameHeader, err := readVirtualMemory(ef, nameAddr, 1+binary.MaxVarintLen64)
	if err != nil {
		return "", err
	}
	nameLen, varintLen := binary.Uvarint(nameHeader[1:])
	if varintLen <= 0 || nameLen > maxGoTypeNameLen {
		return "", errors.New("invalid Go name length")
	}
	nameBytes, err := readVirtualMemory(ef, nameAddr+1+uint64(varintLen), nameLen)
	if err != nil {
		return "", err
	}
	return string(nameBytes), nil
}

func readVirtualMemory(ef *elf.File, addr, size uint64) ([]byte, error) {
	if size > uint64(^uint(0)>>1) || addr > ^uint64(0)-size {
		return nil, errors.New("invalid virtual memory range")
	}
	for _, prog := range ef.Progs {
		if prog.Type != elf.PT_LOAD || addr < prog.Vaddr || addr+size > prog.Vaddr+prog.Filesz {
			continue
		}
		data := make([]byte, int(size))
		if _, err := prog.ReadAt(data, int64(addr-prog.Vaddr)); err != nil {
			return nil, err
		}
		return data, nil
	}

	return nil, errors.New("virtual memory range is not file-backed")
}
