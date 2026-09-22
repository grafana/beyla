// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

type layout struct {
	tables      [tableMax]tableInfo
	stringSize  uint8
	guidSize    uint8
	blobSize    uint8
	simpleSizes [tableMax]uint8
	codedSizes  [codedMax]uint8
}

type tableInfo struct {
	rowCount uint32
	width    uint8
	offset   int
}

// generateLayout generates the bit-accurate layout for the given heapSizes and tableRowCounts.
func generateLayout(heapSizes uint8, tableRowCounts [tableMax]uint32) *layout {
	var la layout
	// String, GUID, and blob index column sizes only depend on the heapSize.
	la.stringSize, la.guidSize, la.blobSize = heapIndexSize(heapSizes)

	// Simple index column sizes only depend on the number of rows of the referenced table.
	for e := range tableMax {
		la.simpleSizes[e] = simpleIndexSize(e, tableRowCounts)
	}

	// Coded index column sizes depend on the maximum number of rows in the set of allowed tables to reference.
	for e := range codedMax {
		la.codedSizes[e] = codedIndexSize(e, tableRowCounts)
	}

	// We now have all the static and dynamic information to calculate the size of each table column.
	var offset int
	for t := range tableMax {
		rowCount := tableRowCounts[t]
		if rowCount == 0 {
			continue
		}
		info := tableInfo{
			rowCount: rowCount,
			offset:   offset,
		}
		info.width += t.width(&la)
		la.tables[t] = info
		offset += int(info.width) * int(rowCount)
	}
	return &la
}

// simpleIndexSize calculates the size of the simple index e.
// Algorithm defined in §II.24.2.6.
func simpleIndexSize(e table, tableRowCounts [tableMax]uint32) uint8 {
	// e is a simple index into a table with index i, it is stored using 2 bytes if table i has
	// less than 2^16 rows, otherwise it is stored using 4 bytes.
	if tableRowCounts[e] < 1<<16 {
		return 2
	}
	return 4
}

// codedIndexSize calculates the size of the coded index e.
// Algorithm defined in §II.24.2.6.
func codedIndexSize(e codedKind, tableRowCounts [tableMax]uint32) uint8 {
	// e is a coded index that points into table t[i] out of n possible tables {t[0], t[n-1]}.
	tables := codedMap[e]
	// The index is stored using 2 bytes if the maximum number of rows of tables is less than 2^(16 – (log2(n))),
	// and using 4 bytes otherwise.
	var maxRowCount uint32
	for _, r := range tables {
		if r != tableNone && tableRowCounts[r] > maxRowCount {
			maxRowCount = tableRowCounts[r]
		}
	}

	var logn byte
	if len(tables) > 0 {
		// We need ceil(log2(n)) to encode n different values (0 to n-1).
		// bits.Len(n-1) gives us the number of bits needed.
		n := uint(len(tables))
		logn = byte(bits.Len(n - 1))
	}
	if maxRowCount < 1<<(16-logn) {
		return 2
	}
	return 4
}

// heapIndexSize calculates the size of indexes into the various heaps.
// The heapSizes field is a bitvector that encodes the width of indexes
// into the various heaps as retrieved from the #~ stream header.
// Algorithm defined in §II.24.2.6.
func heapIndexSize(heapSizes uint8) (strings uint8, guids uint8, blobs uint8) {
	// If bit 0 is set, indexes into the “#String” heap are 4 bytes wide; if bit 1 is set, indexes into the “#GUID” heap are
	// 4 bytes wide; if bit 2 is set, indexes into the “#Blob” heap are 4 bytes wide. Conversely, if the
	// HeapSize bit for a particular heap is not set, indexes into that heap are 2 bytes wide.
	const (
		heapSizesStringBit = 1 << iota
		heapSizesGUIDBit
		heapSizesBlobBit
	)
	sizefn := func(bit uint8) uint8 {
		if heapSizes&bit != 0 {
			return 4
		}
		return 2
	}
	return sizefn(heapSizesStringBit), sizefn(heapSizesGUIDBit), sizefn(heapSizesBlobBit)
}

// ecma335Reader reads data in ecma335 formats that appear in multiple places in the spec.
// This reader is the basis for more advanced readers that parse tables and signatures.
type ecma335Reader struct {
	data   []byte
	layout *layout

	err error
}

func (r *ecma335Reader) uint8() uint8 {
	if r.err != nil {
		return 0
	}
	v := r.data[0]
	r.data = r.data[1:]
	return v
}

func (r *ecma335Reader) uint16() uint16 {
	if r.err != nil {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.data)
	r.data = r.data[2:]
	return v
}

func (r *ecma335Reader) uint32() uint32 {
	if r.err != nil {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.data)
	r.data = r.data[4:]
	return v
}

func (r *ecma335Reader) index(tbl table) Index {
	if r.err != nil {
		return 0
	}
	v := r.uint(r.layout.simpleSizes[tbl])
	if v == 0 {
		r.err = errors.New("record index must be greater than 0")
		return 0
	}
	// ECMA-335 table indices are 1-based, but we follow Go notation instead.
	v -= 1
	if max := r.layout.tables[tbl].rowCount; v > max {
		r.err = fmt.Errorf("record index %d must be smaller than %d", v, max)
		return 0
	}
	return Index(v)
}

func (r *ecma335Reader) uint(size uint8) uint32 {
	switch size {
	case 1:
		return uint32(r.uint8())
	case 2:
		return uint32(r.uint16())
	case 4:
		return r.uint32()
	default:
		panic(fmt.Errorf("columns size %d is not supported", size))
	}
}

func (r *ecma335Reader) compressedUint32() (v uint32) {
	if r.err != nil {
		return
	}
	var n int
	v, n, r.err = decodeCompressedUint32(r.data)
	if r.err != nil {
		return
	}
	r.data = r.data[n:]
	return
}

func (r *ecma335Reader) compressedInt32() (v int32) {
	if r.err != nil {
		return
	}
	var n int
	v, n, r.err = decodeCompressedInt32(r.data)
	if r.err != nil {
		return
	}
	r.data = r.data[n:]
	return
}

// sigReader reads signature data defined in §II.23.2.
type sigReader struct {
	ecma335Reader
}

func (r *sigReader) fieldSig() (v SigField) {
	if r.err != nil {
		return
	}

	firstByte := r.uint8()
	if r.err != nil {
		return
	}
	kind := firstByte & 0xF
	if kind != uint8(sigKind_FIELD) {
		r.err = fmt.Errorf("signature kind is not a field signature: %v", kind)
		return
	}
	if kind&0xF0 != 0 {
		r.err = fmt.Errorf("unexpected data stored in first byte of field signature: %v", kind)
		return
	}
	v.Type = r.decodeType()
	return
}

func (r *sigReader) methodDefSig() (v SigMethodDef) {
	if r.err != nil {
		return
	}

	firstByte := r.uint8()
	if r.err != nil {
		return
	}
	kind := firstByte & 0xF
	if kind > uint8(sigKind_VARARG) {
		r.err = fmt.Errorf("signature kind is not a method def signature: %v", kind)
		return
	}

	thisiness := firstByte & 0xF0
	v.HasThis = thisiness&uint8(sigAbbrev_HASTHIS) != 0
	v.ExplicitThis = thisiness&uint8(sigAbbrev_EXPLICITTHIS) != 0
	if thisiness&uint8(sigAbbrev_GENERIC) != 0 {
		v.Generic = r.compressedUint32()
		if r.err != nil {
			return
		}
	}
	paramCount := r.compressedUint32()
	if r.err != nil {
		return
	}

	v.RetType = r.retType()
	if r.err != nil {
		return
	}
	for range paramCount {
		v.Param = append(v.Param, r.param())
		if r.err != nil {
			return
		}
	}
	return
}

func (r *sigReader) param() (v SigParam) {
	if r.err != nil {
		return
	}
	v.Type = r.decodeType()
	switch v.Type.Kind {
	case ElementType_BYREF:
		v.Kind = SigParamKind_ByRef
	case ElementType_TYPEDBYREF:
		v.Kind = SigParamKind_TypedByRef
	default:
		v.Kind = SigParamKind_ByValue
	}
	return
}

func (r *sigReader) retType() (v SigRetType) {
	if r.err != nil {
		return
	}
	v.Type = r.decodeType()
	switch v.Type.Kind {
	case ElementType_BYREF:
		v.Kind = SigRetTypeKind_ByRef
	case ElementType_TYPEDBYREF:
		v.Kind = SigRetTypeKind_ByRef
	case ElementType_VOID:
		v.Kind = SigRetTypeKind_Void
	default:
		v.Kind = SigRetTypeKind_ByValue
	}
	return
}

func (r *sigReader) customModOpt() (v SigCustomMod) {
	v.Kind = SigCustomModKind_Opt
	v.Index = r.typeHandle()
	return
}

func (r *sigReader) customModReqd() (v SigCustomMod) {
	v.Kind = SigCustomModKind_Reqd
	v.Index = r.typeHandle()
	return
}

// typeHandle reads a type handle (a TypeDefOrRefOrSpecEncoded).
func (r *sigReader) typeHandle() (v CodedIndex[TypeDefOrRefOrSpec]) {
	if r.err != nil {
		return
	}
	value := r.compressedUint32()
	if r.err != nil {
		return
	}
	// Once we decompress the uint32, we could reverse the encoding steps listed in §II.23.2.8, but
	// the coded index algorithm has the same result if we define codedTypeDefOrRefOrSpec.
	v, r.err = parseCoded[TypeDefOrRefOrSpec](value)
	return
}

func (r *sigReader) decodeType() (v SigType) {
	if r.err != nil {
		return
	}
	switch b := ElementType(r.compressedUint32()); b {
	// Use recursion to collect the full list of mods, like the System.Reflection.Metadata impl.
	case ElementType_CMOD_OPT:
		mod := r.customModOpt()
		v = r.decodeType()
		v.Mod = append(v.Mod, mod)
	case ElementType_CMOD_REQD:
		mod := r.customModReqd()
		v = r.decodeType()
		v.Mod = append(v.Mod, mod)

	case ElementType_BYREF:
		v.Kind = b
		v.Value = r.decodeType()

	// TypedByRef and Void have no SigType afterwards.
	case ElementType_TYPEDBYREF:
		v.Kind = ElementType_TYPEDBYREF
	case ElementType_VOID:
		v.Kind = ElementType_VOID

	case ElementType_GENERICINST:
		// See https://github.com/microsoft/go-winmd/issues/19
		r.err = errors.New("generic types are not yet supported")

	case ElementType_CLASS,
		ElementType_VALUETYPE:
		v.Kind = b
		v.Value = r.typeHandle()

	case ElementType_PTR:
		v.Kind = b
		v.Value = r.decodeType()

	case ElementType_ARRAY:
		v.Kind = b
		v.Value = r.array()

	case ElementType_BOOLEAN,
		ElementType_CHAR,
		ElementType_I1,
		ElementType_U1,
		ElementType_I2,
		ElementType_U2,
		ElementType_I4,
		ElementType_U4,
		ElementType_I8,
		ElementType_U8,
		ElementType_R4,
		ElementType_R8,
		ElementType_I,
		ElementType_U,
		ElementType_OBJECT,
		ElementType_STRING:
		v.Kind = b

	default:
		r.err = fmt.Errorf("unsupported element type: %v", b)
	}
	return
}

func (r *sigReader) array() (a SigArray) {
	if r.err != nil {
		return
	}
	a.Type = r.decodeType()
	a.Rank = r.compressedUint32()
	if r.err != nil {
		return
	}
	a.Sizes = make([]uint32, r.compressedUint32())
	for i := range a.Sizes {
		a.Sizes[i] = r.compressedUint32()
	}
	if r.err != nil {
		return
	}
	a.LowerBounds = make([]int32, r.compressedUint32())
	for i := range a.LowerBounds {
		a.LowerBounds[i] = r.compressedInt32()
	}
	return
}

// recordReader reads table record data.
type recordReader struct {
	ecma335Reader
	heaps *heaps
}

// slice reads a Slice from r.
// ownTable is the table code of the table being read.
// targetTable is the table code of the table being referenced.
func (r *recordReader) slice(ownTable, targetTable table) Slice {
	if r.err != nil {
		return Slice{}
	}
	ownWidth := int(r.layout.tables[ownTable].width)

	var sl Slice
	// read first end of the slice so r.i+ownWidth
	// points at the same column of the next row.
	if ownWidth > len(r.data) {
		// there is not enough data to read another row from the current table,
		// so we are peeking from its last row.
		// the spec says that in this case the slice should span until the
		// end of the target table.
		sl.End = Index(r.layout.tables[targetTable].rowCount)
	} else {
		baseData := r.data
		r.data = r.data[ownWidth:]
		sl.End = r.index(targetTable)
		r.data = baseData
	}
	sl.Start = r.index(targetTable)
	if r.err == nil && sl.Start > sl.End {
		r.err = fmt.Errorf("invalid slice end: value=%d, max=%d", sl.End, sl.Start)
		return Slice{}
	}
	if sl.Start == sl.End {
		// this is a valid situation which means range is null.
		return Slice{}
	}
	return sl
}

func (r *recordReader) string() (v String) {
	if r.err != nil {
		return
	}
	idx := r.uint(r.layout.stringSize)
	v, r.err = r.heaps.strs.String(idx)
	return
}

func (r *recordReader) blob() (v []byte) {
	if r.err != nil {
		return
	}
	idx := r.uint(r.layout.blobSize)
	v, r.err = r.heaps.blobs.Bytes(idx)
	return
}

func (r *recordReader) guid() (v [16]byte) {
	if r.err != nil {
		return
	}
	idx := r.uint(r.layout.guidSize)
	if idx == 0 {
		return
	}
	// ECMA-335 GUID indices are 1-based, but we follow Go notation instead.
	v, r.err = r.heaps.guids.GUID(idx - 1)
	return
}
