// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi // import "go.opentelemetry.io/obi/internal/goabi"

import (
	"fmt"
	"sort"

	"go.opentelemetry.io/obi/internal/goversion"
)

const sizeField = "$size"

var (
	go117 = goversion.MustParse("1.17.0")
	go127 = goversion.MustParse("1.27.0")
)

type definition struct {
	Requirement
	query  dwarfQuery
	assign func(*ABI, uint64)
}

func (a *ABI) typeMetadata() *TypeMetadata {
	if a.TypeMetadata == nil {
		a.TypeMetadata = &TypeMetadata{}
	}
	return a.TypeMetadata
}

func moduledataField(
	fieldName string,
	since goversion.Version,
	assign func(*Moduledata, uint64),
) definition {
	return definition{
		Requirement: Requirement{
			OutputType:  "runtime.moduledata",
			OutputField: fieldName,
			Since:       since,
		},
		query: fieldQuery{typeName: "runtime.moduledata", fieldName: fieldName},
		assign: func(abi *ABI, value uint64) {
			assign(&abi.Moduledata, value)
		},
	}
}

func typeMetadataField(
	typeName string,
	fieldName string,
	assign func(*TypeMetadata, uint64),
) definition {
	return definition{
		Requirement: Requirement{
			OutputType:  typeName,
			OutputField: fieldName,
			Since:       go127,
		},
		query: fieldQuery{typeName: typeName, fieldName: fieldName},
		assign: func(abi *ABI, value uint64) {
			assign(abi.typeMetadata(), value)
		},
	}
}

func typeMetadataSize(typeName string, assign func(*TypeMetadata, uint64)) definition {
	return definition{
		Requirement: Requirement{
			OutputType:  typeName,
			OutputField: sizeField,
			Since:       go127,
		},
		query: sizeQuery{typeName: typeName},
		assign: func(abi *ABI, value uint64) {
			assign(abi.typeMetadata(), value)
		},
	}
}

func typeMetadataConstant(
	constantName string,
	outputField string,
	assign func(*TypeMetadata, uint64),
) definition {
	return definition{
		Requirement: Requirement{
			OutputType:  "internal/abi",
			OutputField: outputField,
			Since:       go127,
		},
		query: constantQuery{constantName: constantName},
		assign: func(abi *ABI, value uint64) {
			assign(abi.typeMetadata(), value)
		},
	}
}

var requirementDefinitions = []definition{
	moduledataField("pcHeader", go117, func(m *Moduledata, v uint64) { m.PCHeader = v }),
	moduledataField("pclntable", go117, func(m *Moduledata, v uint64) { m.PCLNTable = v }),
	moduledataField("minpc", go117, func(m *Moduledata, v uint64) { m.MinPC = v }),
	moduledataField("maxpc", go117, func(m *Moduledata, v uint64) { m.MaxPC = v }),
	moduledataField("text", go117, func(m *Moduledata, v uint64) { m.Text = v }),
	moduledataField("etext", go117, func(m *Moduledata, v uint64) { m.EText = v }),
	moduledataField("types", go127, func(m *Moduledata, v uint64) { m.Types = v }),
	moduledataField("typedesclen", go127, func(m *Moduledata, v uint64) { m.TypeDescLen = v }),
	moduledataField("itaboffset", go127, func(m *Moduledata, v uint64) { m.ITabOffset = v }),
	moduledataField("itabsize", go127, func(m *Moduledata, v uint64) { m.ITabSize = v }),

	typeMetadataField("internal/abi.Type", "TFlag", func(m *TypeMetadata, v uint64) { m.TypeTFlagOffset = v }),
	typeMetadataField("internal/abi.Type", "Kind_", func(m *TypeMetadata, v uint64) { m.TypeKindOffset = v }),
	typeMetadataField("internal/abi.Type", "Str", func(m *TypeMetadata, v uint64) { m.TypeNameOffset = v }),
	typeMetadataField("internal/abi.InterfaceType", "Methods", func(m *TypeMetadata, v uint64) { m.InterfaceMethodsOffset = v }),
	typeMetadataField("internal/abi.ITab", "Inter", func(m *TypeMetadata, v uint64) { m.ITabInterOffset = v }),
	typeMetadataField("internal/abi.ITab", "Type", func(m *TypeMetadata, v uint64) { m.ITabTypeOffset = v }),
	typeMetadataField("internal/abi.ITab", "Fun", func(m *TypeMetadata, v uint64) { m.ITabFunOffset = v }),
	typeMetadataField("internal/abi.UncommonType", "PkgPath", func(m *TypeMetadata, v uint64) { m.UncommonPkgPathOffset = v }),
	typeMetadataField("[]internal/abi.Imethod", "len", func(m *TypeMetadata, v uint64) { m.SliceLenOffset = v }),

	typeMetadataSize("internal/abi.Type", func(m *TypeMetadata, v uint64) { m.TypeSize = v }),
	typeMetadataSize("internal/abi.ArrayType", func(m *TypeMetadata, v uint64) { m.ArrayUncommonOffset = v }),
	typeMetadataSize("internal/abi.ChanType", func(m *TypeMetadata, v uint64) { m.ChanUncommonOffset = v }),
	typeMetadataSize("internal/abi.FuncType", func(m *TypeMetadata, v uint64) { m.FuncUncommonOffset = v }),
	typeMetadataSize("internal/abi.InterfaceType", func(m *TypeMetadata, v uint64) { m.InterfaceUncommonOffset = v }),
	typeMetadataSize("internal/abi.MapType", func(m *TypeMetadata, v uint64) { m.MapUncommonOffset = v }),
	typeMetadataSize("internal/abi.PtrType", func(m *TypeMetadata, v uint64) { m.PointerUncommonOffset = v }),
	typeMetadataSize("internal/abi.SliceType", func(m *TypeMetadata, v uint64) { m.SliceUncommonOffset = v }),
	typeMetadataSize("internal/abi.StructType", func(m *TypeMetadata, v uint64) { m.StructUncommonOffset = v }),
	typeMetadataSize("internal/abi.ITab", func(m *TypeMetadata, v uint64) { m.ITabBaseSize = v }),
	typeMetadataSize("internal/abi.TFlag", func(m *TypeMetadata, v uint64) { m.TFlagSize = v }),
	typeMetadataSize("internal/abi.Kind", func(m *TypeMetadata, v uint64) { m.KindSize = v }),
	typeMetadataSize("internal/abi.NameOff", func(m *TypeMetadata, v uint64) { m.NameOffsetSize = v }),

	typeMetadataConstant("internal/abi.TFlagUncommon", "TFlagUncommon", func(m *TypeMetadata, v uint64) { m.TFlagUncommonMask = v }),
	typeMetadataConstant("internal/abi.TFlagExtraStar", "TFlagExtraStar", func(m *TypeMetadata, v uint64) { m.TFlagExtraStarMask = v }),
	typeMetadataConstant("internal/abi.KindDirectIface", "KindDirectIface", func(m *TypeMetadata, v uint64) { m.KindDirectIfaceFlag = v }),
	typeMetadataConstant("internal/abi.Array", "Array", func(m *TypeMetadata, v uint64) { m.ArrayKind = v }),
	typeMetadataConstant("internal/abi.Chan", "Chan", func(m *TypeMetadata, v uint64) { m.ChanKind = v }),
	typeMetadataConstant("internal/abi.Func", "Func", func(m *TypeMetadata, v uint64) { m.FuncKind = v }),
	typeMetadataConstant("internal/abi.Interface", "Interface", func(m *TypeMetadata, v uint64) { m.InterfaceKind = v }),
	typeMetadataConstant("internal/abi.Map", "Map", func(m *TypeMetadata, v uint64) { m.MapKind = v }),
	typeMetadataConstant("internal/abi.Pointer", "Pointer", func(m *TypeMetadata, v uint64) { m.PointerKind = v }),
	typeMetadataConstant("internal/abi.Slice", "Slice", func(m *TypeMetadata, v uint64) { m.SliceKind = v }),
	typeMetadataConstant("internal/abi.Struct", "Struct", func(m *TypeMetadata, v uint64) { m.StructKind = v }),
}

// Requirements returns the ABI facts known to be required for the target version.
// The version selects facts; it does not establish ABI compatibility.
func Requirements(targetVersion goversion.Version) ([]Requirement, error) {
	definitions, err := requiredDefinitions(targetVersion)
	if err != nil {
		return nil, err
	}

	result := make([]Requirement, 0, len(definitions))
	for _, definition := range definitions {
		result = append(result, definition.Requirement)
	}
	return result, nil
}

func requiredDefinitions(targetVersion goversion.Version) ([]definition, error) {
	if targetVersion.Compare(go117) < 0 {
		return nil, fmt.Errorf("unsupported Go version %q", targetVersion)
	}

	result := make([]definition, 0, len(requirementDefinitions))
	for _, definition := range requirementDefinitions {
		if targetVersion.Compare(definition.Since) >= 0 {
			result = append(result, definition)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Key() < result[j].Key()
	})
	return result, nil
}
