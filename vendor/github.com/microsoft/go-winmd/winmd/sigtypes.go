// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

type (
	SigMethodDefBlob []byte
	SigFieldBlob     []byte
	SigPropertyBlob  []byte
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
	VariableParam []Param
}

// StandAloneMethodSig is defined in §II.23.2.3 but is not supported.

// SigField is defined in §II.23.2.4.
type SigField struct {
	Type SigType
}

// SigProperty is defined in §II.23.2.5.
type SigProperty struct {
	HasThis bool
	SigField
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
	Mod  []SigLocalVarMod // empty if Kind is TypedByRef
	Type SigType          // empty if Kind is TypedByRef
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
	Type SigType // empty if Kind is TypedByRef
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
	Type SigType // empty if Kind is TypedByRef or Void
}

// SigType is defined in §II.23.2.12.
type SigType struct {
	Kind  ElementType
	Mod   []SigCustomMod
	Value any // optional
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
	Kind  ElementType
	Value any
}

// SigMethodSpec is defined in §II.23.2.15
type SigMethodSpec []SigType

type SigGenericInst struct {
	Class bool
	Index CodedIndex[TypeDefOrRefOrSpec]
	Type  []SigType
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
)
