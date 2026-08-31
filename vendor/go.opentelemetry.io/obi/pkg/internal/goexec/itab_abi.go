// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"

	trackeroffsets "github.com/grafana/go-offsets-tracker/pkg/offsets"
	"golang.org/x/mod/semver"
)

//go:embed go_abi_offsets.json
var goABIOffsets string

type goTypeMetadataABI struct {
	typeTFlagOffset       uint64
	typeKindOffset        uint64
	typeNameOffset        uint64
	typeSize              uint64
	tflagSize             uint64
	kindSize              uint64
	nameOffsetSize        uint64
	interfaceMethods      uint64
	sliceLenOffset        uint64
	interfaceLenOffset    uint64
	itabTypeOffset        uint64
	itabFunOffset         uint64
	itabBaseSize          uint64
	itabFuncSize          uint64
	uncommonPkgPathOffset uint64
	tflagUncommon         uint64
	tflagExtraStar        uint64
	kindDirectIface       uint64
	kindArray             uint64
	kindChan              uint64
	kindFunc              uint64
	kindInterface         uint64
	kindMap               uint64
	kindPointer           uint64
	kindSlice             uint64
	kindStruct            uint64
	uncommonArray         uint64
	uncommonChan          uint64
	uncommonFunc          uint64
	uncommonInterface     uint64
	uncommonMap           uint64
	uncommonPointer       uint64
	uncommonSlice         uint64
	uncommonStruct        uint64
}

func loadGoTypeMetadataABI(goVersion string) (goTypeMetadataABI, error) {
	track, err := trackeroffsets.Read(bytes.NewBufferString(goABIOffsets))
	if err != nil {
		return goTypeMetadataABI{}, fmt.Errorf("reading generated Go ABI facts: %w", err)
	}

	var abi goTypeMetadataABI
	facts := []struct {
		typeName string
		factName string
		dest     *uint64
	}{
		{"internal/abi.Type", "TFlag", &abi.typeTFlagOffset},
		{"internal/abi.Type", "Kind_", &abi.typeKindOffset},
		{"internal/abi.Type", "Str", &abi.typeNameOffset},
		{"internal/abi.Type", "$size", &abi.typeSize},
		{"internal/abi.TFlag", "$size", &abi.tflagSize},
		{"internal/abi.Kind", "$size", &abi.kindSize},
		{"internal/abi.NameOff", "$size", &abi.nameOffsetSize},
		{"internal/abi.InterfaceType", "Methods", &abi.interfaceMethods},
		{"[]internal/abi.Imethod", "len", &abi.sliceLenOffset},
		{"internal/abi.ITab", "Type", &abi.itabTypeOffset},
		{"internal/abi.ITab", "Fun", &abi.itabFunOffset},
		{"internal/abi.ITab", "$size", &abi.itabBaseSize},
		{"internal/abi.UncommonType", "PkgPath", &abi.uncommonPkgPathOffset},
		{"internal/abi", "TFlagUncommon", &abi.tflagUncommon},
		{"internal/abi", "TFlagExtraStar", &abi.tflagExtraStar},
		{"internal/abi", "KindDirectIface", &abi.kindDirectIface},
		{"internal/abi", "Array", &abi.kindArray},
		{"internal/abi", "Chan", &abi.kindChan},
		{"internal/abi", "Func", &abi.kindFunc},
		{"internal/abi", "Interface", &abi.kindInterface},
		{"internal/abi", "Map", &abi.kindMap},
		{"internal/abi", "Pointer", &abi.kindPointer},
		{"internal/abi", "Slice", &abi.kindSlice},
		{"internal/abi", "Struct", &abi.kindStruct},
		{"internal/abi.ArrayType", "$size", &abi.uncommonArray},
		{"internal/abi.ChanType", "$size", &abi.uncommonChan},
		{"internal/abi.FuncType", "$size", &abi.uncommonFunc},
		{"internal/abi.InterfaceType", "$size", &abi.uncommonInterface},
		{"internal/abi.MapType", "$size", &abi.uncommonMap},
		{"internal/abi.PtrType", "$size", &abi.uncommonPointer},
		{"internal/abi.SliceType", "$size", &abi.uncommonSlice},
		{"internal/abi.StructType", "$size", &abi.uncommonStruct},
	}
	for _, fact := range facts {
		value, err := generatedABIFact(track, fact.typeName, fact.factName, goVersion)
		if err != nil {
			return goTypeMetadataABI{}, err
		}
		*fact.dest = value
	}

	if abi.tflagSize != uint64(binary.Size(uint8(0))) ||
		abi.kindSize != uint64(binary.Size(uint8(0))) ||
		abi.nameOffsetSize != uint64(binary.Size(int32(0))) {
		return goTypeMetadataABI{}, errors.New("unsupported Go runtime ABI scalar sizes")
	}
	maxByte := uint64(^uint8(0))
	if abi.itabBaseSize <= abi.itabFunOffset || abi.kindDirectIface == 0 ||
		abi.tflagUncommon > maxByte || abi.tflagExtraStar > maxByte ||
		abi.kindDirectIface > maxByte || abi.kindArray > maxByte ||
		abi.kindChan > maxByte || abi.kindFunc > maxByte || abi.kindInterface > maxByte ||
		abi.kindMap > maxByte || abi.kindPointer > maxByte || abi.kindSlice > maxByte ||
		abi.kindStruct > maxByte {
		return goTypeMetadataABI{}, errors.New("invalid generated Go runtime ABI facts")
	}
	abi.interfaceLenOffset = abi.interfaceMethods + abi.sliceLenOffset
	abi.itabFuncSize = abi.itabBaseSize - abi.itabFunOffset
	return abi, nil
}

func generatedABIFact(
	track *trackeroffsets.Track,
	typeName string,
	factName string,
	goVersion string,
) (uint64, error) {
	fields, ok := track.Data[typeName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI type %s", typeName)
	}
	fact, ok := fields[factName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s", typeName, factName)
	}

	target := goVersionPattern.FindString(goVersion)
	oldest := goVersionPattern.FindString(fact.Versions.Oldest)
	newest := goVersionPattern.FindString(fact.Versions.Newest)
	if target == "" || oldest == "" || newest == "" ||
		semver.Compare(semver.MajorMinor("v"+target), semver.MajorMinor("v"+oldest)) < 0 ||
		semver.Compare(semver.MajorMinor("v"+target), semver.MajorMinor("v"+newest)) > 0 {
		return 0, fmt.Errorf("go %s runtime ABI is not generated", goVersion)
	}

	value, ok := track.Find(typeName, factName, target)
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s for Go %s", typeName, factName, goVersion)
	}
	return value, nil
}

func (abi goTypeMetadataABI) typeHeaderSize() uint64 {
	size := abi.typeNameOffset + abi.nameOffsetSize
	if end := abi.typeTFlagOffset + abi.tflagSize; end > size {
		size = end
	}
	if end := abi.typeKindOffset + abi.kindSize; end > size {
		size = end
	}
	return size
}

func (abi goTypeMetadataABI) uncommonOffset(kind byte) uint64 {
	kind &= byte(abi.kindDirectIface - 1)
	switch uint64(kind) {
	case abi.kindArray:
		return abi.uncommonArray
	case abi.kindChan:
		return abi.uncommonChan
	case abi.kindFunc:
		return abi.uncommonFunc
	case abi.kindInterface:
		return abi.uncommonInterface
	case abi.kindMap:
		return abi.uncommonMap
	case abi.kindPointer:
		return abi.uncommonPointer
	case abi.kindSlice:
		return abi.uncommonSlice
	case abi.kindStruct:
		return abi.uncommonStruct
	default:
		return abi.typeSize
	}
}
