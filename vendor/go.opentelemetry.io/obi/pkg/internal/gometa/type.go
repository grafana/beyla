// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gometa // import "go.opentelemetry.io/obi/pkg/internal/gometa"

import (
	"encoding/binary"
)

// Kind mirrors reflect.Kind.
type Kind uint8

const (
	Invalid Kind = iota
	Bool
	Int
	Int8
	Int16
	Int32
	Int64
	Uint
	Uint8
	Uint16
	Uint32
	Uint64
	Uintptr
	Float32
	Float64
	Complex64
	Complex128
	Array
	Chan
	Func
	Interface
	Map
	Pointer
	Slice
	String
	Struct
	UnsafePointer
)

func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return "kind?"
}

var kindNames = [...]string{
	Invalid: "invalid", Bool: "bool",
	Int: "int", Int8: "int8", Int16: "int16", Int32: "int32", Int64: "int64",
	Uint: "uint", Uint8: "uint8", Uint16: "uint16", Uint32: "uint32", Uint64: "uint64", Uintptr: "uintptr",
	Float32: "float32", Float64: "float64",
	Complex64: "complex64", Complex128: "complex128",
	Array: "array", Chan: "chan", Func: "func", Interface: "interface", Map: "map",
	Pointer: "pointer", Slice: "slice", String: "string", Struct: "struct", UnsafePointer: "unsafe.Pointer",
}

const rtTypeSize = 48 // sizeof(runtime._type) on 64-bit

const (
	tflagUncommon   = 1 << 0
	tflagExtraStar  = 1 << 1
	tflagNamed      = 1 << 2
	tflagRegularMem = 1 << 3
	kindMask        = 0x1f
	kindDirectIface = 1 << 7
)

// rawType mirrors runtime._type.
type rawType struct {
	Size      uint64
	PtrBytes  uint64
	Hash      uint32
	TFlag     uint8
	Align     uint8
	FieldAlgn uint8
	Kind      uint8
	Equal     uint64
	GCData    uint64
	StrOff    int32
	PtrToThis int32
}

// Type is a decoded _type record.
type Type struct {
	Name  string
	Kind  Kind
	Size  uint64
	TFlag uint8

	w  *Walker
	va uint64
}

// HasMethods reports whether t has an uncommonType block.
func (t *Type) HasMethods() bool { return t.TFlag&tflagUncommon != 0 }

// typeAt returns the cached Type at va, or decodes it.
func (w *Walker) typeAt(va uint64) *Type {
	if t, ok := w.cache[va]; ok {
		return t
	}
	raw, ok := w.readRawType(va)
	if !ok {
		return nil
	}
	t := &Type{
		Size:  raw.Size,
		TFlag: raw.TFlag,
		Kind:  Kind(raw.Kind & kindMask),
		w:     w,
		va:    va,
	}
	t.Name = w.readName(raw.StrOff)
	if t.TFlag&tflagExtraStar != 0 && len(t.Name) > 0 && t.Name[0] == '*' {
		t.Name = t.Name[1:]
	}
	w.cache[va] = t
	return t
}

// readRawType decodes the 48-byte header at va.
func (w *Walker) readRawType(va uint64) (rawType, bool) {
	b, ok := w.rdataSlice(va, rtTypeSize)
	if !ok {
		return rawType{}, false
	}
	return rawType{
		Size:      binary.LittleEndian.Uint64(b[0:8]),
		PtrBytes:  binary.LittleEndian.Uint64(b[8:16]),
		Hash:      binary.LittleEndian.Uint32(b[16:20]),
		TFlag:     b[20],
		Align:     b[21],
		FieldAlgn: b[22],
		Kind:      b[23],
		Equal:     binary.LittleEndian.Uint64(b[24:32]),
		GCData:    binary.LittleEndian.Uint64(b[32:40]),
		StrOff:    int32(binary.LittleEndian.Uint32(b[40:44])),
		PtrToThis: int32(binary.LittleEndian.Uint32(b[44:48])),
	}, true
}

// extOffset is where t's per-kind extension starts.
func (t *Type) extOffset() (uint64, bool) {
	switch t.Kind {
	case Pointer, Slice, Chan, Array, Map, Interface, Struct, Func:
		return rtTypeSize, true
	}
	return 0, false
}

// extSize is the byte size of t's per-kind extension.
func (t *Type) extSize() (uint64, bool) {
	switch t.Kind {
	case Pointer, Slice, Func:
		return 8, true
	case Chan:
		return 16, true
	case Array, Interface, Struct:
		return 32, true
	case Map:
		return 88, true // conservative; Map.uncommon is rare
	}
	return 0, false
}

// readName decodes {flags, LEB128 length, UTF-8} at types_base+off.
func (w *Walker) readName(off int32) string {
	if off == 0 {
		return ""
	}
	va := w.typesBase + uint64(int64(off))
	if _, ok := w.rdataSlice(va, 1); !ok {
		return ""
	}
	p := va + 1 // skip flags byte
	var length uint64
	var shift uint
	for {
		bb, ok := w.rdataSlice(p, 1)
		if !ok {
			return ""
		}
		p++
		length |= uint64(bb[0]&0x7f) << shift
		if bb[0]&0x80 == 0 {
			break
		}
		shift += 7
		if shift > 28 {
			return ""
		}
	}
	if length == 0 {
		return ""
	}
	body, ok := w.rdataSlice(p, int(length))
	if !ok {
		return ""
	}
	return string(body)
}
