// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

type (
	SigMethodDefBlob        []byte
	SigMethodRefBlob        []byte
	SigStandAloneMethodBlob []byte
	SigFieldBlob            []byte
	SigPropertyBlob         []byte
	SigLocalVarsBlob        []byte
	SigTypeSpecBlob         []byte
	SigMethodSpecBlob       []byte
)

// SigMethodDef is defined in §II.23.2.1.
type SigMethodDef struct {
	HasThis      bool
	ExplicitThis bool
	VarArgs      bool
	Generic      uint32
	RetType      SigRetType
	Param        []SigParam
}

// SigMethodRef is defined in §II.23.2.2.
type SigMethodRef struct {
	SigMethodDef
	// VariableParam contains the optional arguments after SENTINEL.
	// The embedded Param contains only the fixed arguments.
	VariableParam []SigParam
}

// SigCallingConvention identifies the calling kind in a method signature.
// It does not include HASTHIS, EXPLICITTHIS, or GENERIC header bits.
type SigCallingConvention uint8

const (
	SigCallingConvention_Default  SigCallingConvention = 0
	SigCallingConvention_Cdecl    SigCallingConvention = 1
	SigCallingConvention_Stdcall  SigCallingConvention = 2
	SigCallingConvention_Thiscall SigCallingConvention = 3
	SigCallingConvention_Fastcall SigCallingConvention = 4
	SigCallingConvention_Vararg   SigCallingConvention = 5
)

// SigStandAloneMethod describes a call-site signature (§II.23.2.3), including
// its managed or unmanaged calling convention. It also represents FNPTR types.
type SigStandAloneMethod struct {
	SigMethodRef
	// CallingConvention distinguishes the calling kinds. The embedded VarArgs
	// is true only for managed VARARG; Cdecl can also have VariableParam entries.
	CallingConvention SigCallingConvention
}

// SigField is defined in §II.23.2.4.
type SigField struct {
	Type SigType
}

// SigProperty is defined in §II.23.2.5.
type SigProperty struct {
	// SigField holds the property type (the getter's result) and its custom modifiers.
	SigField
	// HasThis reports whether the property is an instance property.
	HasThis bool
	// Param contains the index parameters in signature order, excluding the
	// implicit instance and the value supplied to a setter.
	Param []SigParam
}

// SigLocalVars is defined as "LocalVarSig" in §II.23.2.6.
// This type represents the type of all local vars in a method, and the name has been changed for
// clarity and to make it easier to name "SigLocalVar".
type SigLocalVars []SigLocalVar

type SigConstraint struct {
	Pinned bool
}

type SigLocalVarMod struct {
	// Exactly one of Mod and Constraint.Pinned is set.
	Mod        *SigCustomMod
	Constraint SigConstraint
}

type SigLocalVarKind uint8

const (
	SigLocalVarKind_ByValue SigLocalVarKind = iota
	SigLocalVarKind_ByRef
	SigLocalVarKind_TypedByRef
)

type SigLocalVar struct {
	Kind SigLocalVarKind
	// Mod preserves custom modifiers and PINNED constraints in encoded order.
	// It is empty for TypedByRef locals.
	Mod []SigLocalVarMod
	// Type preserves the BYREF wrapper, if present. For TypedByRef, Type.Kind
	// is ElementType_TYPEDBYREF. Leading local modifiers are in Mod, not Type.Mod.
	Type SigType
}

type SigCustomModKind uint8

const (
	SigCustomModKind_Opt SigCustomModKind = iota
	SigCustomModKind_Reqd
)

// SigCustomMod is defined in §II.23.2.7.
type SigCustomMod struct {
	Kind  SigCustomModKind
	Index CodedIndex[TypeDefOrRefOrSpec]
}

type SigParamKind uint8

const (
	SigParamKind_ByValue SigParamKind = iota
	SigParamKind_ByRef
	SigParamKind_TypedByRef
)

// SigParam is defined in §II.23.2.10.
type SigParam struct {
	Kind SigParamKind
	// Type preserves the signature type and its custom modifiers.
	// When Kind is ByRef, Type.Kind is ElementType_BYREF and Type.Value holds
	// the referenced SigType. When Kind is TypedByRef, Type.Kind is
	// ElementType_TYPEDBYREF and Type.Value is nil.
	Type SigType
}

type SigRetTypeKind uint8

const (
	SigRetTypeKind_ByValue SigRetTypeKind = iota
	SigRetTypeKind_ByRef
	SigRetTypeKind_TypedByRef
	SigRetTypeKind_Void
)

// SigRetType is defined in §II.23.2.11.
type SigRetType struct {
	Kind SigRetTypeKind
	// Type preserves the signature type and its custom modifiers.
	// When Kind is ByRef, Type.Kind is ElementType_BYREF and Type.Value holds
	// the referenced SigType. For TypedByRef and Void, Type.Kind is
	// ElementType_TYPEDBYREF or ElementType_VOID, respectively, and Type.Value is nil.
	Type SigType
}

// SigType is defined in §II.23.2.12.
type SigType struct {
	Kind ElementType
	Mod  []SigCustomMod
	// Value holds a CodedIndex[TypeDefOrRefOrSpec] for CLASS and VALUETYPE,
	// a SigType for PTR, BYREF, and SZARRAY, a SigArray for ARRAY, a SigGenericInst
	// for GENERICINST, a SigStandAloneMethod for FNPTR, or a zero-based uint32
	// parameter number for VAR and MVAR.
	// Other supported kinds have a nil Value.
	//
	// For SZARRAY, Value is the element's SigType, not a SigArray. Modifiers
	// following SZARRAY are stored in that element's Mod; this SigType's Mod
	// holds modifiers preceding SZARRAY. The array has rank 1 and lower bound 0,
	// but its length is not encoded in the signature.
	Value any
}

// SigArray is a SigType with an ArrayShape, where ArrayShape is defined in §II.23.2.13.
type SigArray struct {
	Type        SigType
	Rank        uint32
	Sizes       []uint32
	LowerBounds []int32
}

// SigTypeSpec is defined in §II.23.2.14.
type SigTypeSpec struct {
	Kind ElementType
	// Value uses the same representations as SigType.Value. A type specification
	// has no leading custom modifiers; nested types retain their own modifiers.
	Value any
}

// SigMethodSpec is defined in §II.23.2.15
type SigMethodSpec []SigType

// SigGenericInst describes a generic type instantiation (§II.23.2.12).
// Its arguments may be closed types or contain VAR/MVAR generic parameters.
type SigGenericInst struct {
	// Class is true for CLASS and false for VALUETYPE.
	Class bool
	// Index identifies the generic type being instantiated.
	Index CodedIndex[TypeDefOrRefOrSpec]
	// Type contains the generic arguments in their encoded order.
	Type []SigType
}

// ElementType is defined in §II.23.1.16.
type ElementType uint8

const (
	ElementType_END          ElementType = 0x00
	ElementType_VOID         ElementType = 0x01
	ElementType_BOOLEAN      ElementType = 0x02
	ElementType_CHAR         ElementType = 0x03
	ElementType_I1           ElementType = 0x04
	ElementType_U1           ElementType = 0x05
	ElementType_I2           ElementType = 0x06
	ElementType_U2           ElementType = 0x07
	ElementType_I4           ElementType = 0x08
	ElementType_U4           ElementType = 0x09
	ElementType_I8           ElementType = 0x0a
	ElementType_U8           ElementType = 0x0b
	ElementType_R4           ElementType = 0x0c
	ElementType_R8           ElementType = 0x0d
	ElementType_STRING       ElementType = 0x0e
	ElementType_PTR          ElementType = 0x0f
	ElementType_BYREF        ElementType = 0x10
	ElementType_VALUETYPE    ElementType = 0x11
	ElementType_CLASS        ElementType = 0x12
	ElementType_VAR          ElementType = 0x13
	ElementType_ARRAY        ElementType = 0x14
	ElementType_GENERICINST  ElementType = 0x15
	ElementType_TYPEDBYREF   ElementType = 0x16
	ElementType_I            ElementType = 0x18
	ElementType_U            ElementType = 0x19
	ElementType_FNPTR        ElementType = 0x1b
	ElementType_OBJECT       ElementType = 0x1c
	ElementType_SZARRAY      ElementType = 0x1d
	ElementType_MVAR         ElementType = 0x1e
	ElementType_CMOD_REQD    ElementType = 0x1f
	ElementType_CMOD_OPT     ElementType = 0x20
	ElementType_INTERNAL     ElementType = 0x21
	ElementType_MODIFIER     ElementType = 0x40
	ElementType_SENTINEL     ElementType = 0x41
	ElementType_PINNED       ElementType = 0x45
	ElementType_TYPE         ElementType = 0x50
	ElementType_BOXED_OBJECT ElementType = 0x51
	ElementType_RESERVED     ElementType = 0x52
	ElementType_FIELD        ElementType = 0x53
	ElementType_PROPERTY     ElementType = 0x54
	ElementType_ENUM         ElementType = 0x55
)

const (
	sigAbbrev_NONE         = 0x00
	sigAbbrev_GENERIC      = 0x10
	sigAbbrev_HASTHIS      = 0x20
	sigAbbrev_EXPLICITTHIS = 0x40
	sigAbbrev_SENTINEL     = 0x41
)

const (
	// sigKind_DEFAULT (0) through sigKind_VARARG (5) are method signature types.Defined in §II.23.2.3.
	sigKind_DEFAULT = 0x0
	sigKind_C       = 0x1
	sigKind_STDCALL = 0x2
	sigKind_THISCAL = 0x3
	sigKind_FASTCAL = 0x4
	sigKind_VARARG  = 0x5

	// SigKind_FIELD is a FIELD signature. Defined in §II.23.2.4.
	sigKind_FIELD = 0x6

	// SigKind_LOCAL is a local variable signature. Defined in §II.23.2.6.
	sigKind_LOCAL = 0x7

	// SigKind_PROPERTY is a property signature. Defined in §II.23.2.5.
	sigKind_PROPERTY = 0x8

	// sigKind_METHODSPEC introduces generic method arguments (§II.23.2.15).
	sigKind_METHODSPEC = 0xA
)
