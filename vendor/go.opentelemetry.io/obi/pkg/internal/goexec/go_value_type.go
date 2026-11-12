// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"

	"github.com/hashicorp/golang-lru/v2/simplelru"
)

// Go stores the underlying kind in the low five bits of abi.Type.Kind.
const goKindMask = 31

const goTFlagUncommon = 1

// Bound retained metadata when applications panic with many distinct types.
const goValueTypeCacheSize = 128

// GoValueType describes a panic value's type using executable metadata.
type GoValueType struct {
	Kind        uint8
	Methods     bool
	Predeclared bool
	ErrorFunc   string
	GoVersion   string
}

// ValueType reads type metadata at an executable-relative virtual address.
// Callers subtract the process load bias from a runtime type pointer first.
// The type header supplies the kind; optional uncommon metadata supplies the
// method count. Unreadable metadata or an unsupported layout returns false.
func (r *GoSymbolResolver) ValueType(typeAddr uint64) (GoValueType, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.table == nil {
		return GoValueType{}, false
	}

	if r.valueTypes != nil {
		if typ, ok := r.valueTypes.Get(typeAddr); ok {
			return typ, true
		}
	}
	typ, ok := r.readValueType(typeAddr)
	if ok {
		if r.valueTypes == nil {
			// The fixed positive capacity makes construction infallible.
			r.valueTypes, _ = simplelru.NewLRU[uint64, GoValueType](goValueTypeCacheSize, nil)
		}
		r.valueTypes.Add(typeAddr, typ)
	}
	return typ, ok
}

// readValueType requires r.mu; failed reads remain retryable on later panics.
func (r *GoSymbolResolver) readValueType(typeAddr uint64) (GoValueType, bool) {
	var typ goABIType
	data, err := readVirtualMemory(r.executable, typeAddr, uint64(binary.Size(typ)))
	if err != nil {
		return GoValueType{}, false
	}
	if _, err := binary.Decode(data, r.executable.ByteOrder, &typ); err != nil {
		return GoValueType{}, false
	}
	valueType := GoValueType{Kind: typ.Kind & goKindMask, GoVersion: r.goVersion}
	if typ.TFlag&goTFlagUncommon == 0 {
		return valueType, true
	}

	// Uncommon metadata follows the complete kind-specific type header.
	var uncommonOffset int
	var basicKind bool
	switch reflect.Kind(valueType.Kind) {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		uncommonOffset = binary.Size(goABIType{})
		basicKind = true
	case reflect.Pointer:
		uncommonOffset = binary.Size(goPtrType{})
	case reflect.Struct:
		uncommonOffset = binary.Size(goStructType{})
	default:
		return GoValueType{}, false
	}
	if typeAddr > ^uint64(0)-uint64(uncommonOffset) {
		return GoValueType{}, false
	}
	uncommonAddr := typeAddr + uint64(uncommonOffset)
	var uncommon goUncommonType
	data, err = readVirtualMemory(r.executable, uncommonAddr, uint64(binary.Size(uncommon)))
	if err != nil {
		return GoValueType{}, false
	}
	if _, err := binary.Decode(data, r.executable.ByteOrder, &uncommon); err != nil {
		return GoValueType{}, false
	}
	// Built-in basic types have an empty package path; named types carry theirs.
	valueType.Predeclared = basicKind && uncommon.PkgPath == 0
	valueType.Methods = uncommon.Mcount != 0
	if !valueType.Methods {
		return valueType, true
	}
	methods, err := readGoMethods(r.executable, uncommonAddr, uncommon)
	if err != nil {
		return GoValueType{}, false
	}
	textBase, err := r.runtimeTextBase()
	if err != nil {
		return GoValueType{}, false
	}
	for _, method := range methods {
		// Negative offsets mark unavailable code; valid offsets are text-relative.
		if method.Tfn < 0 || textBase > ^uint64(0)-uint64(method.Tfn) {
			continue
		}
		frame, ok := r.pcToFrame(textBase + uint64(method.Tfn))
		if ok && strings.HasSuffix(frame.Function, ".Error") {
			valueType.ErrorFunc = frame.Function
			break
		}
	}
	return valueType, true
}

// readGoMethods reads the method table at uncommonAddr + Moff, where uncommonAddr
// is an executable-relative virtual address. Each entry's Tfn is a signed code
// offset relative to the runtime text base; callers skip negative offsets.
func readGoMethods(executable *elf.File, uncommonAddr uint64, uncommon goUncommonType) ([]goMethod, error) {
	if uncommonAddr > ^uint64(0)-uint64(uncommon.Moff) {
		return nil, errors.New("go method table address overflows")
	}
	// Moff is relative to the uncommon metadata; Mcount is a uint16.
	size := uint64(uncommon.Mcount) * uint64(binary.Size(goMethod{}))
	data, err := readVirtualMemory(executable, uncommonAddr+uint64(uncommon.Moff), size)
	if err != nil {
		return nil, err
	}
	methods := make([]goMethod, int(uncommon.Mcount))
	if _, err := binary.Decode(data, executable.ByteOrder, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

// Mirrors of the internal/abi type layouts on 64-bit targets, unchanged from
// Go 1.17 to 1.27. A type's uncommon data follows its kind-specific struct.
type goABIType struct {
	Size       uint64
	PtrBytes   uint64
	Hash       uint32
	TFlag      uint8
	Align      uint8
	FieldAlign uint8
	Kind       uint8
	Equal      uint64
	GCData     uint64
	Str        int32
	PtrToThis  int32
}

type goPtrType struct {
	goABIType
	Elem uint64
}

type goStructType struct {
	goABIType
	PkgPath uint64
	Fields  [3]uint64
}

type goUncommonType struct {
	PkgPath int32
	Mcount  uint16
	Xcount  uint16
	Moff    uint32
	_       uint32
}

type goMethod struct {
	Name int32
	Mtyp int32
	Ifn  int32
	Tfn  int32
}
