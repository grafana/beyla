// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"debug/pe"
	"fmt"
	"iter"
)

// A Metadata represents an open Windows Metadata file.
type Metadata struct {
	Version string
	Tables  *Tables
	Strings StringHeap
	US      USHeap
	Blob    BlobHeap
	GUID    GUIDHeap

	layout *layout
}

// Open opens a Windows Metadata file at path and returns
// a Metadata struct that provides access to its contents.
func Open(path string) (*Metadata, error) {
	pefile, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer pefile.Close()
	return New(pefile)
}

// New creates a new Metadata from an underlying PE file.
// The PE file can be closed after calling New, as the
// returned Metadata doesn't keep any reference to it.
func New(pefile *pe.File) (*Metadata, error) {
	return newMetadata(pefile)
}

func (m *Metadata) FieldSignature(bytes SigFieldBlob) (SigField, error) {
	r := m.sigReader(bytes)
	return r.fieldSig(), r.err
}

func (m *Metadata) MethodDefSignature(data SigMethodDefBlob) (SigMethodDef, error) {
	r := m.sigReader(data)
	return r.methodDefSig(), r.err
}

func (m *Metadata) sigReader(data []byte) sigReader {
	return sigReader{
		ecma335Reader{
			data:   data,
			layout: m.layout,
		},
	}
}

// Index indexes a record in a table.
type Index uint32

// CodedIndex indexes a record on any table.
type CodedIndex[T CodedTag] struct {
	Index Index
	Tag   T
}

// String is complete UTF8 string from the #String heap
// It does not contain the null-terminated character.
//
// It is used as an optimization to avoid allocating
// when reading from the #Strings heap.
type String struct {
	// Start is the offset in the #Strings heap where the string starts. This is the parameter that
	// was passed to StringHeap.String to create this String. The strings heap doesn't contain
	// duplicate strings, so this value can be used to uniquely identify strings that come from the
	// same heap.
	Start uint32
	data  []byte
}

func (s String) String() string {
	return string(s.data)
}

// Slice indexes the range of records [Start,End) on the table T.
type Slice struct {
	Start Index
	End   Index
}

// Len returns the number of records in the slice.
func (s Slice) Len() uint32 {
	if s.End < s.Start {
		return 0
	}
	return uint32(s.End - s.Start)
}

// All returns a sequence of all indices in the slice.
func (s Slice) All() iter.Seq[Index] {
	return func(yield func(Index) bool) {
		for i := s.Start; i < s.End; i++ {
			if !yield(i) {
				return
			}
		}
	}
}

// Table is a record container as defined in §II.22.
type Table[T any] struct {
	name string
	len  uint32

	decode func(recordReader) (T, error)
	width  uint8
	data   []byte
	heaps  *heaps
	layout *layout
}

func newTable[T any](name string, data []byte, hps *heaps, layout *layout, table table, decode func(recordReader) (T, error)) Table[T] {
	info := layout.tables[table]
	return Table[T]{
		name:   name,
		len:    info.rowCount,
		decode: decode,
		width:  uint8(info.width),
		data:   data[info.offset : info.offset+int(info.width)*int(info.rowCount)],
		heaps:  hps,
		layout: layout,
	}
}

func (t Table[T]) Indices() iter.Seq[Index] {
	return func(yield func(Index) bool) {
		for i := uint32(0); i < t.len; i++ {
			if !yield(Index(i)) {
				return
			}
		}
	}
}

// Len returns the number of records in the table.
func (t Table[T]) Len() uint32 {
	return t.len
}

// Name returns the metadata table name.
func (t Table[T]) Name() string {
	return t.name
}

// At returns the record at row.
func (t Table[T]) At(row Index) (T, error) {
	var zero T
	if uint32(row) >= t.len {
		return zero, fmt.Errorf("row %d is beyond the end of the table", row)
	}
	offset := int(t.width) * int(row)
	r := recordReader{
		ecma335Reader: ecma335Reader{
			data:   t.data[offset:],
			layout: t.layout,
		},
		heaps: t.heaps,
	}
	return t.decode(r)
}
