// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gometa // import "go.opentelemetry.io/obi/pkg/internal/gometa"

import (
	"encoding/binary"
)

// Method is one entry of a type's method table.
type Method struct {
	Name string
	// EntryPC = textBase + Tfn. Zero when body stripped (tfn == -1) or no .text.
	EntryPC uint64
	// FuncType is the signature; nil when linker dropped it.
	FuncType *FuncType
	// TextOff is the raw int32 tfn (-1 means stripped).
	TextOff int32
}

// FuncType is a decoded signature.
type FuncType struct {
	In  []*Type
	Out []*Type
}

const (
	uncommonTypeSize = 16 // sizeof(uncommonType)
	methodEntrySize  = 16 // 4 × int32
	funcTypeHeader   = 8  // InCount + OutCount + pad
)

// Methods returns the method table; nil when t has no uncommon block.
func (t *Type) Methods() []Method {
	if !t.HasMethods() {
		return nil
	}
	uVA, ok := t.uncommonVA()
	if !ok {
		return nil
	}
	u, ok := t.w.rdataSlice(uVA, uncommonTypeSize)
	if !ok {
		return nil
	}
	mcount := binary.LittleEndian.Uint16(u[4:6])
	moff := binary.LittleEndian.Uint32(u[8:12])
	if mcount == 0 {
		return nil
	}
	methodsVA := uVA + uint64(moff)
	out := make([]Method, 0, mcount)
	for i := range mcount {
		mb, ok := t.w.rdataSlice(methodsVA+uint64(i)*methodEntrySize, methodEntrySize)
		if !ok {
			break
		}
		// method record = int32{name, mtyp, ifn, tfn}; ifn (mb[8:12]) skipped.
		nameOff := int32(binary.LittleEndian.Uint32(mb[0:4]))
		mtypOff := int32(binary.LittleEndian.Uint32(mb[4:8]))
		tfnOff := int32(binary.LittleEndian.Uint32(mb[12:16]))
		m := Method{
			Name:    t.w.readName(nameOff),
			TextOff: tfnOff,
		}
		if tfnOff != -1 && t.w.textBase != 0 {
			m.EntryPC = t.w.textBase + uint64(int64(tfnOff))
		}
		if mtypOff > 0 {
			if ft := t.w.funcTypeAt(t.w.typesBase + uint64(int64(mtypOff))); ft != nil {
				m.FuncType = ft
			}
		}
		out = append(out, m)
	}
	return out
}

// uncommonVA returns the VA of t's uncommonType block.
func (t *Type) uncommonVA() (uint64, bool) {
	off, ok := t.extOffset()
	if !ok {
		return 0, false
	}
	size, ok := t.extSize()
	if !ok {
		return 0, false
	}
	return t.va + off + size, true
}

// funcTypeAt decodes a funcType at va.
func (w *Walker) funcTypeAt(va uint64) *FuncType {
	raw, ok := w.readRawType(va)
	if !ok {
		return nil
	}
	if Kind(raw.Kind&kindMask) != Func {
		return nil
	}
	hb, ok := w.rdataSlice(va+rtTypeSize, funcTypeHeader)
	if !ok {
		return nil
	}
	inCount := int(binary.LittleEndian.Uint16(hb[0:2]))
	outCount := int(binary.LittleEndian.Uint16(hb[2:4]) & 0x7fff)
	total := inCount + outCount
	args := va + rtTypeSize + funcTypeHeader
	ft := &FuncType{
		In:  make([]*Type, 0, inCount),
		Out: make([]*Type, 0, outCount),
	}
	for i := range total {
		ab, ok := w.rdataSlice(args+uint64(i)*8, 8)
		if !ok {
			return nil
		}
		argVA := binary.LittleEndian.Uint64(ab)
		argT := w.typeAt(argVA)
		if i < inCount {
			ft.In = append(ft.In, argT)
		} else {
			ft.Out = append(ft.Out, argT)
		}
	}
	return ft
}
