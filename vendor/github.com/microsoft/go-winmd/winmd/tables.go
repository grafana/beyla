// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
package winmd

// AssemblyHashAlgorithm is defined in §II.23.1.1.
type AssemblyHashAlgorithm uint32

const (
	AssemblyHashAlgorithm_None AssemblyHashAlgorithm = 0x0000
	AssemblyHashAlgorithm_MD5  AssemblyHashAlgorithm = 0x8003
	AssemblyHashAlgorithm_SHA1 AssemblyHashAlgorithm = 0x8004
)

// AssemblyFlags is defined in §II.23.1.2.
type AssemblyFlags uint32

const (
	AssemblyFlags_PublicKey                  AssemblyFlags = 0x0001
	AssemblyFlags_Retargetable               AssemblyFlags = 0x0100
	AssemblyFlags_DisableJITcompileOptimizer AssemblyFlags = 0x4000
	AssemblyFlags_EnableJITcompileTracking   AssemblyFlags = 0x8000
)

// Assembly is defined in §II.22.2.
// @table=0x20
type Assembly struct {
	HashAlgID      AssemblyHashAlgorithm
	MajorVersion   uint16
	MinorVersion   uint16
	BuildNumber    uint16
	RevisionNumber uint16
	Flags          AssemblyFlags
	PublicKey      []byte
	Name           String
	Culture        String
}

// assemblyOS is defined in §II.22.3.
// This record should not be emitted into any PE file,
// but needed temporarily to calculate sizes and offsets for subsequent tables.
// @table=0x22
type assemblyOS struct {
	OSPlatformID   uint32
	OSMajorVersion uint32
	OSMinorVersion uint32
}

// assemblyProcessor is defined in §II.22.4.
// This record should not be emitted into any PE file,
// but needed temporarily to calculate sizes and offsets for subsequent tables.
// @table=0x21
type assemblyProcessor struct {
	Processor uint32
}

// AssemblyRef is defined in §II.22.5.
// @table=0x23
type AssemblyRef struct {
	MajorVersion     uint16
	MinorVersion     uint16
	BuildNumber      uint16
	RevisionNumber   uint16
	Flags            AssemblyFlags
	PublicKeyOrToken []byte
	Name             String
	Culture          String
	HashValue        []byte
}

// assemblyRefOS is defined in §II.22.6.
// This record should not be emitted into any PE file,
// but needed temporarily to calculate sizes and offsets for subsequent tables.
// @table=0x25
type assemblyRefOS struct {
	OSPlatformID   uint32
	OSMajorVersion uint32
	OSMinorVersion uint32
	AssemblyRef    Index // @ref=AssemblyRef
}

// assemblyRefProcessor is defined in §II.22.7.
// This record should not be emitted into any PE file,
// but needed temporarily to calculate sizes and offsets for subsequent tables.
// @table=0x24
type assemblyRefProcessor struct {
	Processor   uint32
	AssemblyRef Index // @ref=AssemblyRef
}

// ClassLayout is defined in §II.22.8.
// @table=0x0F
type ClassLayout struct {
	PackingSize uint16
	ClassSize   uint32
	Parent      Index // @ref=TypeDef
}

// Constant is defined in §II.22.9.
// @table=0x0B
type Constant struct {
	Type    ElementType
	Padding byte // 1-byte padding zero
	Parent  CodedIndex[HasConstant]
	Value   []byte
}

// CustomAttribute is defined in §II.22.10.
// @table=0x0C
type CustomAttribute struct {
	Parent CodedIndex[HasCustomAttribute]
	Type   CodedIndex[CustomAttributeType]
	Value  []byte
}

// DeclSecurity is defined in §II.22.11.
// @table=0x0E
type DeclSecurity struct {
	Action        uint16
	Parent        CodedIndex[HasDeclSecurity]
	PermissionSet []byte
}

// EventMap is defined in §II.22.12.
// @table=0x12
type EventMap struct {
	Parent    Index // @ref=TypeDef
	EventList Slice // @ref=Event
}

// EventAttributes is defined in §II.23.1.4.
type EventAttributes uint16

const (
	EventAttributes_SpecialName   EventAttributes = 0x0200
	EventAttributes_RTSpecialName EventAttributes = 0x0400
)

// Event is defined in §II.22.13.
// @table=0x14
type Event struct {
	EventFlags EventAttributes
	Name       String
	EventType  CodedIndex[TypeDefOrRef] // @nullable=true
}

// ExportedType is defined in §II.22.14.
// @table=0x27
type ExportedType struct {
	Flags          TypeAttributes
	TypeDefID      uint32 // index into a TypeDef table, used as hint only
	Name           String
	Namespace      String
	Implementation CodedIndex[Implementation]
}

// FieldAttributes is defined in §II.23.1.5.
// It stores the complete metadata word; use Access and Flags to inspect its parts.
type FieldAttributes uint16

const fieldAccessMask FieldAttributes = 0x0007

// MemberAccess is an exclusive field or method access level (§II.23.1.5, §II.23.1.10).
type MemberAccess uint16

const (
	MemberAccess_CompilerControlled MemberAccess = 0x0000
	MemberAccess_Private            MemberAccess = 0x0001
	MemberAccess_FamANDAssem        MemberAccess = 0x0002
	MemberAccess_Assembly           MemberAccess = 0x0003
	MemberAccess_Family             MemberAccess = 0x0004
	MemberAccess_FamORAssem         MemberAccess = 0x0005
	MemberAccess_Public             MemberAccess = 0x0006
)

// FieldFlags contains independent field flags, not an access level.
type FieldFlags uint16

const (
	FieldFlags_Static          FieldFlags = 0x0010
	FieldFlags_InitOnly        FieldFlags = 0x0020
	FieldFlags_Literal         FieldFlags = 0x0040
	FieldFlags_NotSerialized   FieldFlags = 0x0080
	FieldFlags_HasFieldRVA     FieldFlags = 0x0100
	FieldFlags_SpecialName     FieldFlags = 0x0200
	FieldFlags_RTSpecialName   FieldFlags = 0x0400
	FieldFlags_HasFieldMarshal FieldFlags = 0x1000
	FieldFlags_PInvokeImpl     FieldFlags = 0x2000
	FieldFlags_HasDefault      FieldFlags = 0x8000
)

// Field is defined in §II.22.15.
// @table=0x04
type Field struct {
	Flags     FieldAttributes
	Name      String
	Signature SigFieldBlob
}

// FieldLayout is defined in §II.22.16.
// @table=0x10
type FieldLayout struct {
	Offset uint32
	Field  Index // @ref=Field
}

// FieldMarshal is defined in §II.22.17.
// @table=0x0D
type FieldMarshal struct {
	Parent     CodedIndex[HasFieldMarshal]
	NativeType []byte
}

// FieldRVA is defined in §II.22.18.
// @table=0x1D
type FieldRVA struct {
	RVA   uint32
	Field Index // @ref=Field
}

// FileAttributes is defined in §II.23.1.6.
type FileAttributes uint32

const fileContentMask FileAttributes = 0x0001

// FileContent describes whether a file contains metadata.
type FileContent uint32

const (
	FileContent_ContainsMetaData   FileContent = 0x0000
	FileContent_ContainsNoMetaData FileContent = 0x0001
)

// File is defined in §II.22.19.
// @table=0x26
type File struct {
	Flags     FileAttributes
	Name      String
	HashValue []byte
}

// GenericParamAttributes is defined in §II.23.1.7.
type GenericParamAttributes uint16

const genericVarianceMask GenericParamAttributes = 0x0003

// GenericVariance is the exclusive variance of a generic parameter.
type GenericVariance uint16

const (
	GenericVariance_None          GenericVariance = 0x0000
	GenericVariance_Covariant     GenericVariance = 0x0001
	GenericVariance_Contravariant GenericVariance = 0x0002
)

// GenericConstraints contains the special-constraint bits. Constraints can be
// combined, but ReferenceTypeConstraint and NotNullableValueTypeConstraint are
// mutually incompatible (§II.10.1.7).
type GenericConstraints uint16

const (
	GenericConstraints_ReferenceTypeConstraint        GenericConstraints = 0x0004
	GenericConstraints_NotNullableValueTypeConstraint GenericConstraints = 0x0008
	GenericConstraints_DefaultConstructorConstraint   GenericConstraints = 0x0010
)

// GenericParam is defined in §II.22.20.
// @table=0x2A
type GenericParam struct {
	Number uint16
	Flags  GenericParamAttributes
	Owner  CodedIndex[TypeOrMethodDef]
	Name   String
}

// GenericParam is defined in §II.22.21.
// @table=0x2C
type GenericParamConstraint struct {
	Owner      Index // @ref=GenericParam
	Constraint CodedIndex[TypeDefOrRef]
}

// PInvokeAttributes is defined in §II.23.1.8.
type PInvokeAttributes uint16

const (
	pinvokeCharSetMask           PInvokeAttributes = 0x0006
	pinvokeCallingConventionMask PInvokeAttributes = 0x0700
)

// PInvokeCharSet is the character-set choice for a native import.
type PInvokeCharSet uint16

const (
	PInvokeCharSet_NotSpecified PInvokeCharSet = 0x0000
	PInvokeCharSet_Ansi         PInvokeCharSet = 0x0002
	PInvokeCharSet_Unicode      PInvokeCharSet = 0x0004
	PInvokeCharSet_Auto         PInvokeCharSet = 0x0006
)

// PInvokeCallingConvention is the calling-convention choice for a native import.
type PInvokeCallingConvention uint16

const (
	PInvokeCallingConvention_PlatformAPI PInvokeCallingConvention = 0x0100
	PInvokeCallingConvention_Cdecl       PInvokeCallingConvention = 0x0200
	PInvokeCallingConvention_Stdcall     PInvokeCallingConvention = 0x0300
	PInvokeCallingConvention_Thiscall    PInvokeCallingConvention = 0x0400
	PInvokeCallingConvention_Fastcall    PInvokeCallingConvention = 0x0500
)

// PInvokeFlags contains independent native-import flags.
type PInvokeFlags uint16

const (
	PInvokeFlags_NoMangle          PInvokeFlags = 0x0001
	PInvokeFlags_SupportsLastError PInvokeFlags = 0x0040
)

// ImplMap is defined in §II.22.22.
// @table=0x1C
type ImplMap struct {
	MappingFlags    PInvokeAttributes
	MemberForwarded CodedIndex[MemberForwarded]
	ImportName      String
	ImportScope     Index // @ref=ModuleRef
}

// InterfaceImpl is defined in §II.22.23.
// @table=0x09
type InterfaceImpl struct {
	Class     Index // @ref=TypeDef
	Interface CodedIndex[TypeDefOrRef]
}

// ManifestResourceAttributes is defined in §II.23.1.9.
type ManifestResourceAttributes uint32

const resourceVisibilityMask ManifestResourceAttributes = 0x0007

// ResourceVisibility is an exclusive manifest-resource visibility.
type ResourceVisibility uint32

const (
	ResourceVisibility_Public  ResourceVisibility = 0x0001
	ResourceVisibility_Private ResourceVisibility = 0x0002
)

// ManifestResource is defined in §II.22.24.
// @table=0x28
type ManifestResource struct {
	Offset         uint32
	Flags          ManifestResourceAttributes
	Name           String
	Implementation CodedIndex[Implementation] // @nullable=true
}

// MemberRef is defined in §II.22.25.
// @table=0x0A
type MemberRef struct {
	Class     CodedIndex[MemberRefParent]
	Name      String
	Signature []byte
}

// MethodAttributes is defined in §II.23.1.10.
type MethodAttributes uint16

const (
	methodAccessMask       MethodAttributes = 0x0007
	methodVtableLayoutMask MethodAttributes = 0x0100
)

// MethodVtableLayout selects reuse of an inherited slot or creation of a new slot.
type MethodVtableLayout uint16

const (
	MethodVtableLayout_ReuseSlot MethodVtableLayout = 0x0000
	MethodVtableLayout_NewSlot   MethodVtableLayout = 0x0100
)

// MethodFlags contains independent method flags, not access or slot choices.
type MethodFlags uint16

const (
	MethodFlags_UnmanagedExport  MethodFlags = 0x0008
	MethodFlags_Static           MethodFlags = 0x0010
	MethodFlags_Final            MethodFlags = 0x0020
	MethodFlags_Virtual          MethodFlags = 0x0040
	MethodFlags_HideBySig        MethodFlags = 0x0080
	MethodFlags_Strict           MethodFlags = 0x0200
	MethodFlags_Abstract         MethodFlags = 0x0400
	MethodFlags_SpecialName      MethodFlags = 0x0800
	MethodFlags_RTSpecialName    MethodFlags = 0x1000
	MethodFlags_PInvokeImpl      MethodFlags = 0x2000
	MethodFlags_HasSecurity      MethodFlags = 0x4000
	MethodFlags_RequireSecObject MethodFlags = 0x8000
)

// MethodImplAttributes is defined in §II.23.1.11.
type MethodImplAttributes uint16

const (
	methodCodeTypeMask    MethodImplAttributes = 0x0003
	methodManagednessMask MethodImplAttributes = 0x0004
)

// MethodCodeType selects how a method is implemented.
type MethodCodeType uint16

const (
	MethodCodeType_IL      MethodCodeType = 0x0000
	MethodCodeType_Native  MethodCodeType = 0x0001
	MethodCodeType_OPTIL   MethodCodeType = 0x0002 // Reserved by ECMA-335.
	MethodCodeType_Runtime MethodCodeType = 0x0003
)

// MethodManagedness selects managed or unmanaged implementation code.
type MethodManagedness uint16

const (
	MethodManagedness_Managed   MethodManagedness = 0x0000
	MethodManagedness_Unmanaged MethodManagedness = 0x0004
)

// MethodImplFlags contains independent implementation flags.
type MethodImplFlags uint16

const (
	MethodImplFlags_NoInlining     MethodImplFlags = 0x0008
	MethodImplFlags_ForwardRef     MethodImplFlags = 0x0010
	MethodImplFlags_Synchronized   MethodImplFlags = 0x0020
	MethodImplFlags_NoOptimization MethodImplFlags = 0x0040
	MethodImplFlags_PreserveSig    MethodImplFlags = 0x0080
	MethodImplFlags_InternalCall   MethodImplFlags = 0x1000
)

// MethodDef is defined in §II.22.26.
// @table=0x06
type MethodDef struct {
	RVA       uint32
	ImplFlags MethodImplAttributes
	Flags     MethodAttributes
	Name      String
	Signature SigMethodDefBlob
	ParamList Slice // @ref=Param
}

// MethodImpl is defined in §II.22.27.
// @table=0x19
type MethodImpl struct {
	Class             Index // @ref=TypeDef
	MethodBody        CodedIndex[MethodDefOrRef]
	MethodDeclaration CodedIndex[MethodDefOrRef]
}

// MethodSemanticsAttributes is defined in §II.23.1.12.
type MethodSemanticsAttributes uint16

const (
	MethodSemanticsAttributes_Setter   MethodSemanticsAttributes = 0x0001
	MethodSemanticsAttributes_Getter   MethodSemanticsAttributes = 0x0002
	MethodSemanticsAttributes_Other    MethodSemanticsAttributes = 0x0004
	MethodSemanticsAttributes_AddOn    MethodSemanticsAttributes = 0x0008
	MethodSemanticsAttributes_RemoveOn MethodSemanticsAttributes = 0x0010
	MethodSemanticsAttributes_Fire     MethodSemanticsAttributes = 0x0020
)

// MethodImpl is defined in §II.22.28.
// @table=0x18
type MethodSemantics struct {
	Semantics   MethodSemanticsAttributes
	Method      Index // @ref=MethodDef
	Association CodedIndex[HasSemantics]
}

// MethodSpec is defined in §II.22.29.
// @table=0x2B
type MethodSpec struct {
	Method        CodedIndex[MethodDefOrRef]
	Instantiation SigMethodSpecBlob
}

// Module is defined in §II.22.30.
// @table=0x00
type Module struct {
	Generation uint16
	Name       String
	Mvid       [16]byte
	EncID      [16]byte
	EncBaseID  [16]byte
}

// ModuleRef is defined in §II.22.31.
// @table=0x1A
type ModuleRef struct {
	Name String
}

// NestedClass is defined in §II.22.32.
// @table=0x29
type NestedClass struct {
	NestedClass    Index // @ref=TypeDef
	EnclosingClass Index // @ref=TypeDef
}

// ParamAttributes is defined in §II.23.1.13.
type ParamAttributes uint16

const (
	ParamAttributes_In              ParamAttributes = 0x0001
	ParamAttributes_Out             ParamAttributes = 0x0002
	ParamAttributes_Optional        ParamAttributes = 0x0010
	ParamAttributes_HasDefault      ParamAttributes = 0x1000
	ParamAttributes_HasFieldMarshal ParamAttributes = 0x2000
)

// Param is defined in §II.22.33.
// @table=0x08
type Param struct {
	Flags    ParamAttributes
	Sequence uint16
	Name     String
}

// PropertyAttributes is defined in §II.23.1.14.
type PropertyAttributes uint16

const (
	PropertyAttributes_SpecialName   PropertyAttributes = 0x0200
	PropertyAttributes_RTSpecialName PropertyAttributes = 0x0400
	PropertyAttributes_HasDefault    PropertyAttributes = 0x1000
)

// Property is defined in §II.22.34.
// @table=0x17
type Property struct {
	Flags PropertyAttributes
	Name  String
	Type  SigPropertyBlob
}

// PropertyMap is defined in §II.22.35.
// @table=0x15
type PropertyMap struct {
	Parent       Index // @ref=TypeDef
	PropertyList Slice // @ref=Property
}

// StandAloneSig is defined in §II.22.36.
// @table=0x11
type StandAloneSig struct {
	Signature []byte
}

// TypeAttributes is defined in §II.23.1.15.
// It stores the complete metadata word; its accessors separate choices from flags.
type TypeAttributes uint32

const (
	typeVisibilityMask   TypeAttributes = 0x00000007
	typeLayoutMask       TypeAttributes = 0x00000018
	typeSemanticsMask    TypeAttributes = 0x00000020
	typeStringFormatMask TypeAttributes = 0x00030000
)

// TypeVisibility is the exclusive visibility of a type.
type TypeVisibility uint32

const (
	TypeVisibility_NotPublic         TypeVisibility = 0x00000000
	TypeVisibility_Public            TypeVisibility = 0x00000001
	TypeVisibility_NestedPublic      TypeVisibility = 0x00000002
	TypeVisibility_NestedPrivate     TypeVisibility = 0x00000003
	TypeVisibility_NestedFamily      TypeVisibility = 0x00000004
	TypeVisibility_NestedAssembly    TypeVisibility = 0x00000005
	TypeVisibility_NestedFamANDAssem TypeVisibility = 0x00000006
	TypeVisibility_NestedFamORAssem  TypeVisibility = 0x00000007
)

// IsNested reports whether the visibility is one of the six nested-type choices.
// It returns false for unnamed encodings.
func (v TypeVisibility) IsNested() bool {
	return v >= TypeVisibility_NestedPublic && v <= TypeVisibility_NestedFamORAssem
}

// TypeLayout selects automatic, sequential, or explicit layout.
type TypeLayout uint32

const (
	TypeLayout_AutoLayout       TypeLayout = 0x00000000
	TypeLayout_SequentialLayout TypeLayout = 0x00000008
	TypeLayout_ExplicitLayout   TypeLayout = 0x00000010
)

// TypeSemantics distinguishes classes from interfaces.
type TypeSemantics uint32

const (
	TypeSemantics_Class     TypeSemantics = 0x00000000
	TypeSemantics_Interface TypeSemantics = 0x00000020
)

// TypeStringFormat selects how native-interoperability strings are interpreted.
type TypeStringFormat uint32

const (
	TypeStringFormat_AnsiClass         TypeStringFormat = 0x00000000
	TypeStringFormat_UnicodeClass      TypeStringFormat = 0x00010000
	TypeStringFormat_AutoClass         TypeStringFormat = 0x00020000
	TypeStringFormat_CustomFormatClass TypeStringFormat = 0x00030000
)

// TypeFlags contains independent type flags. Custom string-format bits remain
// opaque in TypeAttributes and are not exposed as independent flags.
type TypeFlags uint32

const (
	TypeFlags_Abstract        TypeFlags = 0x00000080
	TypeFlags_Sealed          TypeFlags = 0x00000100
	TypeFlags_SpecialName     TypeFlags = 0x00000400
	TypeFlags_RTSpecialName   TypeFlags = 0x00000800
	TypeFlags_Import          TypeFlags = 0x00001000
	TypeFlags_Serializable    TypeFlags = 0x00002000
	TypeFlags_HasSecurity     TypeFlags = 0x00040000
	TypeFlags_BeforeFieldInit TypeFlags = 0x00100000
	TypeFlags_IsTypeForwarder TypeFlags = 0x00200000
)

// TypeDef is defined in §II.22.37.
// @table=0x02
type TypeDef struct {
	Flags      TypeAttributes
	Name       String
	Namespace  String
	Extends    CodedIndex[TypeDefOrRef] // @nullable=true
	FieldList  Slice                    // @ref=Field
	MethodList Slice                    // @ref=MethodDef
}

// TypeRef is defined in §II.22.38.
// @table=0x01
type TypeRef struct {
	ResolutionScope CodedIndex[ResolutionScope] // @nullable=true
	Name            String
	Namespace       String
}

// TypeSpec is defined in §II.22.39.
// @table=0x1B
type TypeSpec struct {
	Signature SigTypeSpecBlob
}
