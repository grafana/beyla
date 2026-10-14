// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package goabi discovers the private Go runtime ABI used by OBI.
package goabi // import "go.opentelemetry.io/obi/internal/goabi"

import "go.opentelemetry.io/obi/internal/goversion"

// Requirement describes one versioned ABI fact and its generated output key.
type Requirement struct {
	OutputType  string
	OutputField string
	Since       goversion.Version
}

// Key returns the generated type-and-field key for a requirement.
func (r Requirement) Key() string {
	return r.OutputType + "." + r.OutputField
}

// Fact is a resolved ABI requirement and value.
type Fact struct {
	Requirement Requirement
	Value       uint64
}

// Moduledata contains the runtime.moduledata field offsets OBI reads.
type Moduledata struct {
	PCHeader    uint64
	PCLNTable   uint64 // Offset of the pclntable slice header.
	MinPC       uint64
	MaxPC       uint64
	Text        uint64
	EText       uint64
	Types       uint64
	TypeDescLen uint64
	ITabOffset  uint64
	ITabSize    uint64
}

// TypeMetadata contains the internal/abi layout used to decode Go type data.
type TypeMetadata struct {
	TypeTFlagOffset         uint64
	TypeKindOffset          uint64
	TypeNameOffset          uint64
	InterfaceMethodsOffset  uint64
	SliceLenOffset          uint64
	ITabInterOffset         uint64
	ITabTypeOffset          uint64
	ITabFunOffset           uint64
	UncommonPkgPathOffset   uint64
	ArrayUncommonOffset     uint64
	ChanUncommonOffset      uint64
	FuncUncommonOffset      uint64
	InterfaceUncommonOffset uint64
	MapUncommonOffset       uint64
	PointerUncommonOffset   uint64
	SliceUncommonOffset     uint64
	StructUncommonOffset    uint64

	TypeSize       uint64
	TFlagSize      uint64
	KindSize       uint64
	NameOffsetSize uint64
	ITabBaseSize   uint64

	TFlagUncommonMask   uint64
	TFlagExtraStarMask  uint64
	KindDirectIfaceFlag uint64
	ArrayKind           uint64
	ChanKind            uint64
	FuncKind            uint64
	InterfaceKind       uint64
	MapKind             uint64
	PointerKind         uint64
	SliceKind           uint64
	StructKind          uint64
}

// ABI is one complete, validated set of ABI facts for a Go version.
type ABI struct {
	Moduledata Moduledata
	// TypeMetadata is nil when the selected requirements do not include type metadata.
	TypeMetadata *TypeMetadata
	facts        []Fact
}

// Facts returns the resolved facts in stable key order.
func (a ABI) Facts() []Fact {
	return append([]Fact(nil), a.facts...)
}

// TypeHeaderSize returns the number of bytes needed to decode a Go type header.
func (metadata *TypeMetadata) TypeHeaderSize() uint64 {
	size := metadata.TypeNameOffset + metadata.NameOffsetSize
	if end := metadata.TypeTFlagOffset + metadata.TFlagSize; end > size {
		size = end
	}
	if end := metadata.TypeKindOffset + metadata.KindSize; end > size {
		size = end
	}
	return size
}

// InterfaceMethodCountOffset returns the offset of the method slice's length.
func (metadata *TypeMetadata) InterfaceMethodCountOffset() uint64 {
	return metadata.InterfaceMethodsOffset + metadata.SliceLenOffset
}

// ITabFuncEntrySize returns the size of one function-table entry in an itab.
func (metadata *TypeMetadata) ITabFuncEntrySize() uint64 {
	return metadata.ITabBaseSize - metadata.ITabFunOffset
}

// UncommonTypeOffset returns the offset of uncommon type data for kind.
func (metadata *TypeMetadata) UncommonTypeOffset(kind byte) uint64 {
	kind &= byte(metadata.KindDirectIfaceFlag - 1)
	switch uint64(kind) {
	case metadata.ArrayKind:
		return metadata.ArrayUncommonOffset
	case metadata.ChanKind:
		return metadata.ChanUncommonOffset
	case metadata.FuncKind:
		return metadata.FuncUncommonOffset
	case metadata.InterfaceKind:
		return metadata.InterfaceUncommonOffset
	case metadata.MapKind:
		return metadata.MapUncommonOffset
	case metadata.PointerKind:
		return metadata.PointerUncommonOffset
	case metadata.SliceKind:
		return metadata.SliceUncommonOffset
	case metadata.StructKind:
		return metadata.StructUncommonOffset
	default:
		return metadata.TypeSize
	}
}
