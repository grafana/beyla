// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"debug/pe"
	"errors"
	"fmt"
	"iter"
)

// Metadata provides access to Windows Metadata loaded into memory by [Open]
// or [New]. Returned tables, rows, and heap views remain valid after the source
// file is closed and do not require the Metadata itself to be retained.
//
// Treat the metadata, its tables, and its heap bytes as read-only. Concurrent
// reads and calls to Metadata methods are safe while this data and any input
// blobs remain unchanged. [CustomAttributeDecoder] has separate concurrency rules.
//
// The signature-decoding methods also work on a zero-value Metadata.
// They still check the blob's format, but cannot check whether referenced
// table rows exist. A Metadata returned by [Open] or [New] performs both checks.
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
// It closes the file before returning. On error, it returns nil metadata.
// Like [New], it does not eagerly decode every row or signature.
func Open(path string) (*Metadata, error) {
	pefile, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer pefile.Close()
	return New(pefile)
}

// New loads the metadata from pefile into memory without retaining a reference
// to the file. It does not close pefile; the caller owns it and may close it
// after this call.
// A #~ tables stream is required; uncompressed #- streams are not supported.
// On success, Tables is non-nil, even when all tables are empty.
// Rows and signatures are decoded on access, so success does not mean every
// row or blob is valid. On error, it returns nil metadata.
func New(pefile *pe.File) (*Metadata, error) {
	return newMetadata(pefile)
}

// FieldSignature decodes an entire field signature blob, rejecting trailing data.
// It leaves the input unchanged and returns independently owned signature data.
// On error, the result may be partial and must be discarded.
// Type nesting is limited to 64 levels.
// Type handle bounds are checked when table metadata is available.
// Generic instantiations and VAR/MVAR parameter numbers are preserved without
// substitution or validation against a declaring type's or method's constraints.
func (m *Metadata) FieldSignature(bytes SigFieldBlob) (SigField, error) {
	r := m.sigReader(bytes)
	sig := r.fieldSig()
	if r.err == nil && len(r.data) != 0 {
		r.err = errors.New("trailing field signature data")
	}
	return sig, r.err
}

// MethodDefSignature decodes an entire method definition signature blob, rejecting trailing data.
// It leaves the input unchanged and returns independently owned signature data.
// On error, the result may be partial and must be discarded.
// Type nesting is limited to 64 levels per return type or parameter.
// Type handle bounds are checked when table metadata is available.
// Generic instantiations and VAR/MVAR parameter numbers are preserved without
// substitution or validation against a declaring type's or method's constraints.
func (m *Metadata) MethodDefSignature(data SigMethodDefBlob) (SigMethodDef, error) {
	r := m.sigReader(data)
	sig := r.methodDefSig()
	if r.err == nil && len(r.data) != 0 {
		r.err = errors.New("trailing method definition signature data")
	}
	return sig, r.err
}

// MethodRefSignature decodes an entire method reference signature from
// [MemberRef.Signature], rejecting trailing data. Fixed and optional VARARG
// parameters are kept separately in Param and VariableParam.
// It leaves the input unchanged and returns independently owned signature data.
// On error, the result may be partial and must be discarded.
// Type nesting, including function-pointer signatures, is limited to 64 levels.
// Type handle bounds are checked when table metadata is available. Generic
// parameter numbers are preserved without substitution or constraint checking.
func (m *Metadata) MethodRefSignature(data SigMethodRefBlob) (SigMethodRef, error) {
	r := m.sigReader(data)
	sig := r.methodSig(methodSigAllowGeneric|methodSigAllowSentinel, 0).SigMethodRef
	if r.err == nil && len(r.data) != 0 {
		r.err = errors.New("trailing method reference signature data")
	}
	return sig, r.err
}

// StandAloneMethodSignature decodes an entire calli signature from
// [StandAloneSig.Signature], rejecting trailing data. Managed and unmanaged
// calling conventions are preserved; VARARG and Cdecl may have optional
// parameters after SENTINEL. Standalone signatures cannot declare generic
// parameters, but their types may refer to enclosing generic parameters.
// It leaves the input unchanged and returns independently owned signature data.
// On error, the result may be partial and must be discarded.
// Type nesting, including function-pointer signatures, is limited to 64 levels.
// Type handle bounds are checked when table metadata is available.
func (m *Metadata) StandAloneMethodSignature(data SigStandAloneMethodBlob) (SigStandAloneMethod, error) {
	r := m.sigReader(data)
	sig := r.methodSig(methodSigAllowUnmanaged|methodSigAllowSentinel, 0)
	if r.err == nil && len(r.data) != 0 {
		r.err = errors.New("trailing standalone method signature data")
	}
	return sig, r.err
}

// PropertySignature decodes an entire property signature blob, rejecting trailing data.
// The blob is stored in [Property.Type].
// It leaves the input unchanged and returns independently owned signature data.
// On error, the result may be partial and must be discarded.
// Type nesting is limited to 64 levels per property type or index parameter.
// Type handle bounds are checked when table metadata is available.
// Generic instantiations and VAR/MVAR parameter numbers are preserved without
// substitution or validation against a declaring type's or method's constraints.
func (m *Metadata) PropertySignature(data SigPropertyBlob) (SigProperty, error) {
	r := m.sigReader(data)
	sig := r.propertySig()
	if r.err == nil && len(r.data) != 0 {
		r.err = errors.New("trailing property signature data")
	}
	return sig, r.err
}

// LocalVarsSignature decodes an entire local variable signature from
// [StandAloneSig.Signature], rejecting trailing data. It preserves the encoded
// order of custom modifiers and PINNED constraints. There must be 1 to 65534
// locals. Type nesting is limited to 64 levels per local, including nested
// function-pointer signatures. Type handle bounds are checked when table
// metadata is available; pinning eligibility and generic constraints are not.
// It leaves the input unchanged and returns independently owned signature data.
// On error, the result may be partial and must be discarded.
func (m *Metadata) LocalVarsSignature(data SigLocalVarsBlob) (SigLocalVars, error) {
	r := m.sigReader(data)
	sig := r.localVarsSig()
	if r.err == nil && len(r.data) != 0 {
		r.err = errors.New("trailing local variable signature data")
	}
	return sig, r.err
}

// TypeSpecSignature decodes an entire type specification from [TypeSpec.Signature],
// rejecting trailing data. There is no calling-convention byte. The type can
// contain open generic parameter references; leading custom modifiers, BYREF,
// TYPEDBYREF, and VOID are not permitted in this context.
// It leaves the input unchanged and returns independently owned signature data.
// On error, the result may be partial and must be discarded.
// Type nesting, including function-pointer signatures, is limited to 64 levels.
// Type handle bounds are checked when table metadata is available.
func (m *Metadata) TypeSpecSignature(data SigTypeSpecBlob) (SigTypeSpec, error) {
	r := m.sigReader(data)
	typ := r.decodeType(0, 0)
	if r.err == nil && len(r.data) != 0 {
		r.err = errors.New("trailing type specification signature data")
	}
	return SigTypeSpec{Kind: typ.Kind, Value: typ.Value}, r.err
}

// MethodSpecSignature decodes an entire generic method instantiation from
// [MethodSpec.Instantiation], rejecting trailing data. At least one type argument
// is required. Type nesting is limited to 64 levels per argument, and type
// handle bounds are checked when table metadata is available. Generic parameter
// numbers are preserved without substitution or checking the target's arity
// or constraints.
// It leaves the input unchanged and returns independently owned signature data.
// On error, the result may be partial and must be discarded.
func (m *Metadata) MethodSpecSignature(data SigMethodSpecBlob) (SigMethodSpec, error) {
	r := m.sigReader(data)
	sig := r.methodSpecSig()
	if r.err == nil && len(r.data) != 0 {
		r.err = errors.New("trailing method specification signature data")
	}
	return sig, r.err
}

func (m *Metadata) sigReader(data []byte) sigReader {
	return sigReader{
		ecma335Reader{
			data:   data,
			layout: m.layout,
		},
	}
}

// Index is a zero-based row index in a metadata table. Decoding converts the
// one-based row numbers stored in the file to this representation. Zero denotes
// the first row, not an absent reference.
type Index uint32

// CodedIndex identifies a zero-based row Index in the table selected by Tag.
// A null reference is represented by the tag family's Null value, when one
// exists; its Index has no meaning. The zero value is not a null reference.
type CodedIndex[T CodedTag] struct {
	Index Index
	Tag   T
}

// String is a read-only view of a UTF-8 string in the #Strings heap, excluding
// its terminating NUL. It shares and keeps alive the heap's backing bytes.
// The zero value represents an empty string.
type String struct {
	// Start is the offset in the #Strings heap where the string starts. This is the parameter that
	// was passed to [StringHeap.String] to create this String. Equal strings can be stored at
	// different offsets, so Start identifies a heap location, not a unique string value.
	Start uint32
	data  []byte
}

// String returns a Go string independent of the heap's backing bytes.
func (s String) String() string {
	return string(s.data)
}

// Slice identifies the half-open range of zero-based row indices [Start, End)
// in a metadata table. Its zero value is empty; it does not contain row data.
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

// Table is a record container as defined in §II.22. Copies share the same
// read-only backing data, and rows are decoded on demand by [Table.At] or [Table.All].
// The zero value is an empty table.
type Table[T any] struct {
	name string
	len  uint32

	decode func(recordReader) (T, string, error)
	width  uint8
	data   []byte
	heaps  *heaps
	layout *layout
}

func newTable[T any](name string, data []byte, hps *heaps, layout *layout, table table, decode func(recordReader) (T, string, error)) Table[T] {
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

// Indices returns the zero-based row indices without decoding the records.
func (t Table[T]) Indices() iter.Seq[Index] {
	return func(yield func(Index) bool) {
		for i := uint32(0); i < t.len; i++ {
			if !yield(Index(i)) {
				return
			}
		}
	}
}

// All returns an iterator over decoded records in row order.
// Each iteration starts at row zero and decodes records on demand.
// It stops when yield returns false or after yielding the first error.
// Records have the ownership and error-result contracts described by [Table.At].
// Use [Table.Indices] when row indices are needed.
func (t Table[T]) All() iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		r := recordReader{
			ecma335Reader: ecma335Reader{data: t.data, layout: t.layout},
			heaps:         t.heaps,
		}
		decode := t.decode
		for row := range t.len {
			record, column, err := decode(r)
			if err != nil {
				err = &DecodeError{Table: t.name, Row: Index(row), Column: column, Err: err}
			}
			if !yield(record, err) || err != nil {
				return
			}
			// Keep the full remaining table available for list-column lookahead.
			r.data = r.data[t.width:]
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

// DecodeError describes a failure to read a metadata table row.
// The underlying error is available through [errors.Is] and [errors.As].
type DecodeError struct {
	// Table is the metadata table name. It is empty for a zero-value Table.
	Table string
	// Row is the zero-based index of the row being decoded. For list lookahead
	// errors, this is the current row, not the subsequent row being inspected.
	Row Index
	// Column is the Go field name of the first column that failed to decode.
	// It is empty when no column was read, such as for an out-of-range row.
	Column string
	// Err is the underlying decoding or bounds error.
	Err error
}

func (e *DecodeError) Error() string {
	table := e.Table
	if table == "" {
		table = "table"
	}
	if e.Column != "" {
		return fmt.Sprintf("%s[%d].%s: %v", table, e.Row, e.Column, e.Err)
	}
	return fmt.Sprintf("%s[%d]: %v", table, e.Row, e.Err)
}

// Unwrap returns the underlying error.
func (e *DecodeError) Unwrap() error {
	return e.Err
}

// At decodes and returns the record at the zero-based row index.
// The record is returned by value, but its String and blob fields share the
// metadata heaps. Treat those bytes as read-only; copy blobs before modifying
// them. Changing other fields of the returned record does not change metadata.
// Null coded indices are accepted only in columns that permit them.
// On failure, the error is a *DecodeError identifying the table, zero-based row,
// and column, when applicable. The record may be partial and must be discarded.
func (t Table[T]) At(row Index) (T, error) {
	var zero T
	if uint32(row) >= t.len {
		return zero, &DecodeError{Table: t.name, Row: row, Err: fmt.Errorf("row %d is beyond the end of the table", row)}
	}
	offset := int(t.width) * int(row)
	r := recordReader{
		ecma335Reader: ecma335Reader{
			data:   t.data[offset:],
			layout: t.layout,
		},
		heaps: t.heaps,
	}
	rec, column, err := t.decode(r)
	if err != nil {
		return rec, &DecodeError{Table: t.name, Row: row, Column: column, Err: err}
	}
	return rec, nil
}
