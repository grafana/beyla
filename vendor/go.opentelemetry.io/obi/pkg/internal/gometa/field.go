// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gometa // import "go.opentelemetry.io/obi/pkg/internal/gometa"

import (
	"encoding/binary"
)

// Field is one struct field.
type Field struct {
	Name     string
	Type     *Type
	Offset   uint64
	Embedded bool
}

const structFieldSize = 24 // sizeof(runtime.structField): {*name, *_type, uintptr}

// PackagePath returns the import path stored with a struct's unexported fields.
func (t *Type) PackagePath() string {
	if t.Kind != Struct {
		return ""
	}
	data, ok := t.w.rdataSlice(t.va+rtTypeSize, 8)
	if !ok {
		return ""
	}
	path, _ := t.w.readFieldName(binary.LittleEndian.Uint64(data))
	return path
}

// Fields returns t's fields; nil if t is not a struct.
func (t *Type) Fields() []Field {
	if t.Kind != Struct {
		return nil
	}
	// structType layout after rtType: PkgPath (8B) + Fields slice header (24B).
	hdrVA := t.va + rtTypeSize + 8
	hdr, ok := t.w.rdataSlice(hdrVA, 24)
	if !ok {
		return nil
	}
	data := binary.LittleEndian.Uint64(hdr[0:8])
	flen := binary.LittleEndian.Uint64(hdr[8:16])
	if flen == 0 || flen > 1<<16 {
		return nil
	}
	out := make([]Field, 0, flen)
	for i := range flen {
		fb, ok := t.w.rdataSlice(data+i*structFieldSize, structFieldSize)
		if !ok {
			return nil
		}
		nameVA := binary.LittleEndian.Uint64(fb[0:8])
		typVA := binary.LittleEndian.Uint64(fb[8:16])
		off := binary.LittleEndian.Uint64(fb[16:24])
		name, embedded := t.w.readFieldName(nameVA)
		out = append(out, Field{
			Name:     name,
			Type:     t.w.typeAt(typVA),
			Offset:   off,
			Embedded: embedded,
		})
	}
	return out
}

// readFieldName decodes a structField name at va (absolute); flags bit 3 = embedded.
func (w *Walker) readFieldName(va uint64) (string, bool) {
	if va == 0 {
		return "", false
	}
	fb, ok := w.rdataSlice(va, 1)
	if !ok {
		return "", false
	}
	flags := fb[0]
	embedded := flags&0x08 != 0
	p := va + 1
	var length uint64
	var shift uint
	for {
		bb, ok := w.rdataSlice(p, 1)
		if !ok {
			return "", embedded
		}
		p++
		length |= uint64(bb[0]&0x7f) << shift
		if bb[0]&0x80 == 0 {
			break
		}
		shift += 7
		if shift > 28 {
			return "", embedded
		}
	}
	if length == 0 {
		return "", embedded
	}
	body, ok := w.rdataSlice(p, int(length))
	if !ok {
		return "", embedded
	}
	return string(body), embedded
}

// Elem returns the element type for Pointer/Slice/Chan/Array.
func (t *Type) Elem() *Type {
	switch t.Kind {
	case Pointer, Slice, Chan, Array:
	default:
		return nil
	}
	eb, ok := t.w.rdataSlice(t.va+rtTypeSize, 8)
	if !ok {
		return nil
	}
	return t.w.typeAt(binary.LittleEndian.Uint64(eb))
}
