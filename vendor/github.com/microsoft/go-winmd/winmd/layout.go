// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
// It checks that all table rows fit within dataSize bytes.
func generateLayout(heapSizes uint8, tableRowCounts [tableMax]uint32, dataSize int) (*layout, error) {
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
			width:    t.width(&la),
		}
		// Check the size before converting to int, which may be 32 bits.
		size := uint64(info.width) * uint64(rowCount)
		if size > uint64(dataSize-offset) {
			return nil, fmt.Errorf("table %d exceeds the tables stream: %w", t, io.ErrUnexpectedEOF)
		}
		la.tables[t] = info
		offset += int(size)
	}
	return &la, nil
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
	if len(r.data) < 1 {
		r.err = io.ErrUnexpectedEOF
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
	if len(r.data) < 2 {
		r.err = io.ErrUnexpectedEOF
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
	if len(r.data) < 4 {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.LittleEndian.Uint32(r.data)
	r.data = r.data[4:]
	return v
}

func (r *ecma335Reader) index(tbl table) Index {
	v := r.listIndex(tbl)
	if r.err != nil {
		return 0
	}
	if max := r.layout.tables[tbl].rowCount; uint32(v) >= max {
		r.err = fmt.Errorf("record index %d must be smaller than %d", v, max)
		return 0
	}
	return v
}

// listIndex also allows the index one past the last row, for empty lists
// and the end of the preceding row's list.
func (r *ecma335Reader) listIndex(tbl table) Index {
	if r.err != nil {
		return 0
	}
	v := r.uint(r.layout.simpleSizes[tbl])
	return r.listIndexValue(tbl, v)
}

func (r *ecma335Reader) listIndexValue(tbl table, v uint32) Index {
	if r.err != nil {
		return 0
	}
	if v == 0 {
		r.err = errors.New("record index must be greater than 0")
		return 0
	}
	// ECMA-335 table indices are 1-based, but we follow Go notation instead.
	v -= 1
	if max := r.layout.tables[tbl].rowCount; v > max {
		r.err = fmt.Errorf("list index %d must be at most %d", v, max)
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
	v, n, r.err = DecodeCompressedUint32(r.data)
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
	v, n, r.err = DecodeCompressedInt32(r.data)
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

const maxSignatureDepth = 64

// sigTypeOptions permits prefixes and special types in specific signature
// contexts (FieldSig, PropertySig, Param, RetType, pointer targets, and vector elements).
type sigTypeOptions uint8

const (
	sigTypeAllowCustomMod sigTypeOptions = 1 << iota
	sigTypeAllowVoid
	sigTypeAllowByRef
	sigTypeAllowTypedByRef
)

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
	if firstByte&0xF0 != 0 {
		r.err = fmt.Errorf("unexpected data stored in first byte of field signature: %v", firstByte)
		return
	}
	v.Type = r.decodeType(sigTypeAllowCustomMod, 0)
	return
}

type methodSigOptions uint8

const (
	methodSigAllowGeneric methodSigOptions = 1 << iota
	methodSigAllowSentinel
	methodSigAllowUnmanaged
)

func (r *sigReader) methodDefSig() SigMethodDef {
	return r.methodSig(methodSigAllowGeneric, 0).SigMethodDef
}

// methodSig decodes the common method grammar without resetting type depth.
// Function-pointer return and parameter types inherit the enclosing depth;
// sibling types each get an independent budget.
func (r *sigReader) methodSig(allow methodSigOptions, depth int) (v SigStandAloneMethod) {
	if r.err != nil {
		return
	}

	firstByte := r.uint8()
	if r.err != nil {
		return
	}
	kind := firstByte & 0xF
	if kind > sigKind_VARARG || kind != sigKind_DEFAULT && kind != sigKind_VARARG && allow&methodSigAllowUnmanaged == 0 {
		r.err = fmt.Errorf("unsupported method signature calling convention: %#x", kind)
		return
	}
	if firstByte&0x80 != 0 {
		r.err = errors.New("reserved bit set in method signature header")
		return
	}
	v.CallingConvention = SigCallingConvention(kind)
	v.VarArgs = kind == sigKind_VARARG

	thisiness := firstByte & 0xF0
	v.HasThis = thisiness&uint8(sigAbbrev_HASTHIS) != 0
	v.ExplicitThis = thisiness&uint8(sigAbbrev_EXPLICITTHIS) != 0
	if v.ExplicitThis && !v.HasThis {
		r.err = errors.New("EXPLICITTHIS requires HASTHIS in method signature")
		return
	}
	if thisiness&uint8(sigAbbrev_GENERIC) != 0 {
		if allow&methodSigAllowGeneric == 0 || kind != sigKind_DEFAULT {
			r.err = errors.New("generic parameters are not permitted in this method signature")
			return
		}
		v.Generic = r.compressedUint32()
		if r.err != nil {
			return
		}
		if v.Generic == 0 {
			r.err = errors.New("generic method signature must declare at least one generic parameter")
			return
		}
	}
	paramCount := r.compressedUint32()
	if r.err != nil {
		return
	}

	v.RetType = r.retType(depth)
	if r.err != nil {
		return
	}
	// Each parameter requires at least one byte. Never allocate from an
	// unchecked count, including inside a function-pointer signature.
	if uint64(paramCount) > uint64(len(r.data)) {
		r.err = io.ErrUnexpectedEOF
		return
	}
	variable := false
	for range paramCount {
		if len(r.data) != 0 && r.data[0] == sigAbbrev_SENTINEL {
			if allow&methodSigAllowSentinel == 0 || kind != sigKind_VARARG && kind != sigKind_C {
				r.err = errors.New("SENTINEL is not permitted in this method signature")
				return
			}
			if variable {
				r.err = errors.New("multiple SENTINEL markers in method signature")
				return
			}
			r.data = r.data[1:]
			variable = true
		}
		param := r.param(depth)
		if r.err != nil {
			return
		}
		if variable {
			v.VariableParam = append(v.VariableParam, param)
		} else {
			v.Param = append(v.Param, param)
		}
	}
	return
}

func (r *sigReader) propertySig() (v SigProperty) {
	if r.err != nil {
		return
	}
	firstByte := r.uint8()
	if r.err != nil {
		return
	}
	kind := firstByte & 0xF
	if kind != uint8(sigKind_PROPERTY) {
		r.err = fmt.Errorf("signature kind is not a property signature: %v", kind)
		return
	}
	if firstByte&^uint8(sigKind_PROPERTY|sigAbbrev_HASTHIS) != 0 {
		r.err = fmt.Errorf("unexpected data stored in first byte of property signature: %v", firstByte)
		return
	}
	v.HasThis = firstByte&uint8(sigAbbrev_HASTHIS) != 0
	paramCount := r.compressedUint32()
	if r.err != nil {
		return
	}
	// PropertySig uses CustomMod* Type, not RetType, for the property type.
	v.Type = r.decodeType(sigTypeAllowCustomMod, 0)
	if r.err != nil {
		return
	}
	// Each index parameter consumes at least one byte. Reject impossible
	// counts before allocating, then append only successfully decoded entries.
	if uint64(paramCount) > uint64(len(r.data)) {
		r.err = io.ErrUnexpectedEOF
		return
	}
	for range paramCount {
		param := r.param(0)
		if r.err != nil {
			return
		}
		v.Param = append(v.Param, param)
	}
	return
}

func (r *sigReader) localVarsSig() (v SigLocalVars) {
	if header := r.uint8(); r.err != nil {
		return
	} else if header != sigKind_LOCAL {
		r.err = errors.New("invalid local variable signature header")
		return
	}
	count := r.compressedUint32()
	if r.err != nil {
		return
	}
	if count == 0 || count > 0xfffe {
		r.err = errors.New("local variable count must be between 1 and 65534")
		return
	}
	if uint64(count) > uint64(len(r.data)) {
		r.err = io.ErrUnexpectedEOF
		return
	}
	for range count {
		local := r.localVar()
		if r.err != nil {
			return
		}
		v = append(v, local)
	}
	return
}

func (r *sigReader) localVar() (v SigLocalVar) {
	for r.err == nil {
		before := r.data
		kind := r.compressedUint32()
		if r.err != nil {
			return
		}
		switch kind {
		case uint32(ElementType_CMOD_OPT), uint32(ElementType_CMOD_REQD):
			mod := SigCustomMod{Kind: SigCustomModKind_Opt, Index: r.typeHandle()}
			if r.err != nil {
				return
			}
			if kind == uint32(ElementType_CMOD_REQD) {
				mod.Kind = SigCustomModKind_Reqd
			}
			v.Mod = append(v.Mod, SigLocalVarMod{Mod: &mod})
		case uint32(ElementType_PINNED):
			v.Mod = append(v.Mod, SigLocalVarMod{Constraint: SigConstraint{Pinned: true}})
		case uint32(ElementType_TYPEDBYREF):
			if len(v.Mod) != 0 {
				r.err = errors.New("TYPEDBYREF locals cannot have modifiers or constraints")
				return
			}
			v.Kind = SigLocalVarKind_TypedByRef
			v.Type.Kind = ElementType_TYPEDBYREF
			return
		default:
			// Let the shared type decoder consume the complete type, including
			// a BYREF wrapper. Local prefixes are already preserved in Mod.
			r.data = before
			v.Type = r.decodeType(sigTypeAllowByRef, 0)
			if v.Type.Kind == ElementType_BYREF {
				v.Kind = SigLocalVarKind_ByRef
			}
			return
		}
	}
	return
}

func (r *sigReader) methodSpecSig() SigMethodSpec {
	if header := r.uint8(); r.err != nil {
		return nil
	} else if header != sigKind_METHODSPEC {
		r.err = errors.New("invalid method specification signature header")
		return nil
	}
	return r.genericArguments(0)
}

func (r *sigReader) param(depth int) (v SigParam) {
	if r.err != nil {
		return
	}
	v.Type = r.decodeType(sigTypeAllowCustomMod|sigTypeAllowByRef|sigTypeAllowTypedByRef, depth)
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

func (r *sigReader) retType(depth int) (v SigRetType) {
	if r.err != nil {
		return
	}
	v.Type = r.decodeType(sigTypeAllowCustomMod|sigTypeAllowVoid|sigTypeAllowByRef|sigTypeAllowTypedByRef, depth)
	switch v.Type.Kind {
	case ElementType_BYREF:
		v.Kind = SigRetTypeKind_ByRef
	case ElementType_TYPEDBYREF:
		v.Kind = SigRetTypeKind_TypedByRef
	case ElementType_VOID:
		v.Kind = SigRetTypeKind_Void
	default:
		v.Kind = SigRetTypeKind_ByValue
	}
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
	if value == 0 {
		r.err = errors.New("signature type handle must not be null")
		return
	}
	// Once we decompress the uint32, we could reverse the encoding steps listed in §II.23.2.8, but
	// the coded index algorithm has the same result if we define codedTypeDefOrRefOrSpec.
	v, r.err = parseCoded[TypeDefOrRefOrSpec](value)
	if r.err != nil {
		return
	}
	if r.layout != nil {
		// Standalone signatures can be decoded without a metadata layout.
		// When one is available, validate the target just as for table references.
		tbl, _ := codedTable(codedTypeDefOrRefOrSpec, uint8(v.Tag))
		if count := r.layout.tables[tbl].rowCount; uint32(v.Index) >= count {
			r.err = fmt.Errorf("signature type index %d is beyond the end of table %d (%d rows)", v.Index, tbl, count)
			return CodedIndex[TypeDefOrRefOrSpec]{}
		}
	}
	return
}

func (r *sigReader) decodeType(allow sigTypeOptions, depth int) (v SigType) {
	if r.err != nil {
		return
	}
	if depth >= maxSignatureDepth {
		r.err = errors.New("signature type nesting limit exceeded")
		return
	}
	var b ElementType
	for {
		code := r.compressedUint32()
		if r.err != nil {
			return
		}
		if code > 0xff {
			r.err = fmt.Errorf("unsupported element type: %#x", code)
			return
		}
		b = ElementType(code)
		if b != ElementType_CMOD_OPT && b != ElementType_CMOD_REQD {
			break
		}
		if allow&sigTypeAllowCustomMod == 0 {
			r.err = errors.New("custom modifiers are not allowed in this signature context")
			return
		}
		mod := SigCustomMod{Kind: SigCustomModKind_Opt, Index: r.typeHandle()}
		if r.err != nil {
			return
		}
		if b == ElementType_CMOD_REQD {
			mod.Kind = SigCustomModKind_Reqd
		}
		// Keep the encoded order without recursing through modifier prefixes.
		v.Mod = append(v.Mod, mod)
	}
	switch b {
	case ElementType_BYREF:
		if allow&sigTypeAllowByRef == 0 {
			r.err = errors.New("BYREF is not allowed in this signature context")
			return
		}
		v.Kind = b
		v.Value = r.decodeType(0, depth+1)

	// TypedByRef and Void have no SigType afterwards.
	case ElementType_TYPEDBYREF:
		if allow&sigTypeAllowTypedByRef == 0 {
			r.err = errors.New("TYPEDBYREF is not allowed in this signature context")
			return
		}
		v.Kind = ElementType_TYPEDBYREF
	case ElementType_VOID:
		if allow&sigTypeAllowVoid == 0 {
			r.err = errors.New("VOID is not allowed in this signature context")
			return
		}
		v.Kind = ElementType_VOID

	case ElementType_GENERICINST:
		v.Kind = b
		v.Value = r.genericInst(depth)

	case ElementType_VAR, ElementType_MVAR:
		v.Kind = b
		// Generic parameter numbers are zero-based, unlike metadata row indexes.
		v.Value = r.compressedUint32()

	case ElementType_CLASS,
		ElementType_VALUETYPE:
		v.Kind = b
		v.Value = r.typeHandle()

	case ElementType_PTR:
		v.Kind = b
		v.Value = r.decodeType(sigTypeAllowCustomMod|sigTypeAllowVoid, depth+1)

	case ElementType_FNPTR:
		v.Kind = b
		v.Value = r.methodSig(methodSigAllowGeneric|methodSigAllowSentinel|methodSigAllowUnmanaged, depth+1)

	case ElementType_SZARRAY:
		v.Kind = b
		v.Value = r.decodeType(sigTypeAllowCustomMod, depth+1)

	case ElementType_ARRAY:
		v.Kind = b
		v.Value = r.array(depth)

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

func (r *sigReader) genericInst(depth int) (inst SigGenericInst) {
	kind := r.compressedUint32()
	if r.err != nil {
		return
	}
	if kind != uint32(ElementType_CLASS) && kind != uint32(ElementType_VALUETYPE) {
		r.err = fmt.Errorf("generic instantiation must specify CLASS or VALUETYPE, got %#x", kind)
		return
	}
	inst.Class = kind == uint32(ElementType_CLASS)
	inst.Index = r.typeHandle()
	if r.err != nil {
		return
	}
	inst.Type = r.genericArguments(depth + 1)
	return
}

// genericArguments is shared by type and method instantiations.
func (r *sigReader) genericArguments(depth int) (arguments []SigType) {
	count := r.compressedUint32()
	if r.err != nil {
		return
	}
	if count == 0 {
		r.err = errors.New("generic instantiation must have at least one type argument")
		return
	}
	// Every argument consumes at least one byte. Reject impossible counts
	// before allocating, then grow only as valid arguments are decoded.
	if uint64(count) > uint64(len(r.data)) {
		r.err = io.ErrUnexpectedEOF
		return
	}
	for range count {
		arg := r.decodeType(0, depth)
		if r.err != nil {
			return
		}
		// Type admits pointers, but generic instantiations do not (§II.9.4).
		// VOID, BYREF, and TYPEDBYREF are already rejected by decodeType.
		if arg.Kind == ElementType_PTR || arg.Kind == ElementType_FNPTR {
			r.err = errors.New("unmanaged pointers cannot be generic type arguments")
			return
		}
		arguments = append(arguments, arg)
	}
	return
}

func (r *sigReader) array(depth int) (a SigArray) {
	if r.err != nil {
		return
	}
	a.Type = r.decodeType(0, depth+1)
	a.Rank = r.compressedUint32()
	if r.err != nil {
		return
	}
	if a.Rank == 0 {
		r.err = errors.New("array rank must be greater than zero")
		return
	}
	count := r.arrayShapeCount(a.Rank)
	if r.err != nil {
		return
	}
	a.Sizes = make([]uint32, count)
	for i := range a.Sizes {
		a.Sizes[i] = r.compressedUint32()
		if r.err != nil {
			return
		}
	}
	count = r.arrayShapeCount(a.Rank)
	if r.err != nil {
		return
	}
	a.LowerBounds = make([]int32, count)
	for i := range a.LowerBounds {
		a.LowerBounds[i] = r.compressedInt32()
		if r.err != nil {
			return
		}
	}
	return
}

// arrayShapeCount bounds each dimension count before allocating its slice.
func (r *sigReader) arrayShapeCount(rank uint32) uint32 {
	count := r.compressedUint32()
	if r.err != nil {
		return 0
	}
	if count > rank {
		r.err = fmt.Errorf("array shape count %d exceeds rank %d", count, rank)
		return 0
	}
	// Each size or lower bound requires at least one byte in the signature.
	if uint64(count) > uint64(len(r.data)) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	return count
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
	indexSize := r.layout.simpleSizes[targetTable]
	baseData := r.data
	start := r.uint(indexSize)
	if r.err != nil {
		return Slice{}
	}
	// TypeDef.FieldList and MethodList may be null (§II.22.37).
	// MethodDef.ParamList may also be null when no parameter rows are owned.
	nullable := ownTable == tableTypeDef || ownTable == tableMethodDef
	if nullable && start == 0 {
		return Slice{}
	}
	sl := Slice{
		Start: r.listIndexValue(targetTable, start),
		End:   Index(r.layout.tables[targetTable].rowCount),
	}
	if r.err != nil {
		return Slice{}
	}
	// Look ahead at the same column in subsequent rows. Null lists own no
	// entries and do not bound the preceding non-null run; skip them until
	// the next non-null list or the end of the table.
	for remaining := baseData; ownWidth < len(remaining); {
		remaining = remaining[ownWidth:]
		next := ecma335Reader{data: remaining, layout: r.layout}
		end := next.uint(indexSize)
		if next.err != nil {
			r.err = next.err
			return Slice{}
		}
		if nullable && end == 0 {
			continue
		}
		sl.End = r.listIndexValue(targetTable, end)
		if r.err != nil {
			return Slice{}
		}
		break
	}
	if sl.Start > sl.End {
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
	if r.err != nil {
		return
	}
	v, r.err = r.heaps.strs.String(idx)
	return
}

func (r *recordReader) blob() (v []byte) {
	if r.err != nil {
		return
	}
	idx := r.uint(r.layout.blobSize)
	if r.err != nil {
		return
	}
	// Zero is a null blob reference, including when the empty heap is omitted.
	if idx == 0 {
		return nil
	}
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
