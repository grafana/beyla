// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gometa // import "go.opentelemetry.io/obi/pkg/internal/gometa"

import (
	"errors"
	"fmt"
)

// Encoding tells BPF how to extract a value from pt_regs.
type Encoding uint8

const (
	EncRegScalar        Encoding = 1 + iota // scalar in RegOff
	EncGoString                             // {data, len} in RegOff, LenReg
	EncPtrFieldScalar                       // scalar at *(RegOff + FieldOff)
	EncPtrFieldGoString                     // Go string at *(RegOff + FieldOff)
)

func (e Encoding) String() string {
	switch e {
	case EncRegScalar:
		return "reg-scalar"
	case EncGoString:
		return "reg-gostring"
	case EncPtrFieldScalar:
		return "ptr-field-scalar"
	case EncPtrFieldGoString:
		return "ptr-field-gostring"
	default:
		return "encoding?"
	}
}

// ArgRecipe extracts one primitive value from a function's args.
type ArgRecipe struct {
	Name     string
	Kind     Kind
	Size     uint8
	Signed   bool
	Encoding Encoding
	RegOff   int
	LenReg   int
	FieldOff uint64
}

// BuildArgRecipe emits recipes for the primitive args of a Go function.
// Set isMethod for methods (receiver consumes one int reg, not extracted).
// Skips floats, slices, maps, chans, interfaces, nested struct ptrs, stack-spilled args.
func BuildArgRecipe(ft *FuncType, isMethod bool, arch Arch) ([]ArgRecipe, error) {
	if ft == nil {
		return nil, errors.New("gometa: nil FuncType")
	}
	regs := regList(arch)
	if regs == nil {
		return nil, fmt.Errorf("gometa: unsupported arch %v", arch)
	}
	alloc := newRegAllocator(arch)
	if isMethod {
		if _, ok := alloc.take(1); !ok {
			return nil, errors.New("gometa: no register for receiver")
		}
	}
	out := make([]ArgRecipe, 0, len(ft.In))
	for i, arg := range ft.In {
		name := fmt.Sprintf("arg%d", i)
		emitted, ok := emitForArg(name, arg, alloc)
		if !ok {
			return out, fmt.Errorf("gometa: arg %d (%v) does not fit in int regs", i, arg)
		}
		out = append(out, emitted...)
	}
	return out, nil
}

func emitForArg(name string, t *Type, alloc *regAllocator) ([]ArgRecipe, bool) {
	if t == nil {
		return nil, true
	}
	switch t.Kind {
	case Bool, Int, Int8, Int16, Int32, Int64,
		Uint, Uint8, Uint16, Uint32, Uint64, Uintptr, UnsafePointer:
		slots, ok := alloc.take(1)
		if !ok {
			return nil, false
		}
		return []ArgRecipe{{
			Name:     name,
			Kind:     t.Kind,
			Size:     scalarSize(t),
			Signed:   isSigned(t.Kind),
			Encoding: EncRegScalar,
			RegOff:   slots[0],
		}}, true

	case String:
		slots, ok := alloc.take(2)
		if !ok {
			return nil, false
		}
		return []ArgRecipe{{
			Name:     name,
			Kind:     String,
			Encoding: EncGoString,
			RegOff:   slots[0],
			LenReg:   slots[1],
		}}, true

	case Pointer:
		slots, ok := alloc.take(1)
		if !ok {
			return nil, false
		}
		elem := t.Elem()
		if elem == nil || elem.Kind != Struct {
			// opaque pointer → emit as 8-byte unsigned scalar
			return []ArgRecipe{{
				Name:     name,
				Kind:     Uintptr,
				Size:     8,
				Encoding: EncRegScalar,
				RegOff:   slots[0],
			}}, true
		}
		var out []ArgRecipe
		for _, f := range elem.Fields() {
			// skip unexported — usually codegen noise (proto sizeCache, state, ...)
			if f.Type == nil || !isExported(f.Name) {
				continue
			}
			fname := name + "." + f.Name
			if rec, ok := emitForField(fname, f, slots[0]); ok {
				out = append(out, rec...)
			}
		}
		return out, true

	case Slice:
		alloc.skip(3)
		return nil, true
	case Interface:
		alloc.skip(2)
		return nil, true
	case Float32, Float64, Complex64, Complex128:
		// float regs (XMM/V) aren't in pt_regs; skip without consuming int slot
		return nil, true
	case Chan, Map, Func:
		alloc.skip(1)
		return nil, true
	default:
		return nil, false
	}
}

func emitForField(name string, f Field, ptrReg int) ([]ArgRecipe, bool) {
	switch f.Type.Kind {
	case Bool, Int, Int8, Int16, Int32, Int64,
		Uint, Uint8, Uint16, Uint32, Uint64, Uintptr, UnsafePointer:
		return []ArgRecipe{{
			Name:     name,
			Kind:     f.Type.Kind,
			Size:     scalarSize(f.Type),
			Signed:   isSigned(f.Type.Kind),
			Encoding: EncPtrFieldScalar,
			RegOff:   ptrReg,
			FieldOff: f.Offset,
		}}, true
	case String:
		return []ArgRecipe{{
			Name:     name,
			Kind:     String,
			Encoding: EncPtrFieldGoString,
			RegOff:   ptrReg,
			FieldOff: f.Offset,
		}}, true
	default:
		return nil, false
	}
}

func scalarSize(t *Type) uint8 {
	if t.Size > 8 {
		return 8
	}
	return uint8(t.Size)
}

func isSigned(k Kind) bool {
	switch k {
	case Int, Int8, Int16, Int32, Int64:
		return true
	}
	return false
}

// isExported reports whether name starts with an uppercase ASCII letter.
func isExported(name string) bool {
	if name == "" {
		return false
	}
	c := name[0]
	return c >= 'A' && c <= 'Z'
}
