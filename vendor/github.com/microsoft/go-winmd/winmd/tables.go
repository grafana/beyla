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
	EventType  CodedIndex[TypeDefOrRef]
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
type FieldAttributes uint16

const (
	FieldAttributes_FieldAccessMask    FieldAttributes = 0x0007
	FieldAttributes_CompilerControlled FieldAttributes = 0x0000
	FieldAttributes_Private            FieldAttributes = 0x0001
	FieldAttributes_FamANDAssem        FieldAttributes = 0x0002
	FieldAttributes_Assembly           FieldAttributes = 0x0003
	FieldAttributes_Family             FieldAttributes = 0x0004
	FieldAttributes_FamORAssem         FieldAttributes = 0x0005
	FieldAttributes_Public             FieldAttributes = 0x0006
	FieldAttributes_Static             FieldAttributes = 0x0010
	FieldAttributes_InitOnly           FieldAttributes = 0x0020
	FieldAttributes_Literal            FieldAttributes = 0x0040
	FieldAttributes_NotSerialized      FieldAttributes = 0x0080
	FieldAttributes_SpecialName        FieldAttributes = 0x0200
	FieldAttributes_PInvokeImpl        FieldAttributes = 0x2000
	FieldAttributes_RTSpecialName      FieldAttributes = 0x0400
	FieldAttributes_HasFieldMarshal    FieldAttributes = 0x1000
	FieldAttributes_HasDefault         FieldAttributes = 0x8000
	FieldAttributes_HasFieldRVA        FieldAttributes = 0x0100
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
type FileAttributes uint16

const (
	FileAttributes_ContainsMetaData   FileAttributes = 0x0000
	FileAttributes_ContainsNoMetaData FileAttributes = 0x0001
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

const (
	GenericParamAttributes_VarianceMask                   GenericParamAttributes = 0x0003
	GenericParamAttributes_None                           GenericParamAttributes = 0x0000
	GenericParamAttributes_Covariant                      GenericParamAttributes = 0x0001
	GenericParamAttributes_Contravariant                  GenericParamAttributes = 0x0002
	GenericParamAttributes_SpecialConstraintMask          GenericParamAttributes = 0x001C
	GenericParamAttributes_ReferenceTypeConstraint        GenericParamAttributes = 0x0004
	GenericParamAttributes_NotNullableValueTypeConstraint GenericParamAttributes = 0x0008
	GenericParamAttributes_DefaultConstructorConstraint   GenericParamAttributes = 0x0010
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
	PInvokeAttributes_NoMangle            PInvokeAttributes = 0x0001
	PInvokeAttributes_CharSetMask         PInvokeAttributes = 0x0006
	PInvokeAttributes_CharSetNotSpec      PInvokeAttributes = 0x0000
	PInvokeAttributes_CharSetAnsi         PInvokeAttributes = 0x0002
	PInvokeAttributes_CharSetUnicode      PInvokeAttributes = 0x0004
	PInvokeAttributes_CharSetAuto         PInvokeAttributes = 0x0006
	PInvokeAttributes_SupportsLastError   PInvokeAttributes = 0x0040
	PInvokeAttributes_CallConvMask        PInvokeAttributes = 0x0700
	PInvokeAttributes_CallConvPlatformapi PInvokeAttributes = 0x0100
	PInvokeAttributes_CallConvCdecl       PInvokeAttributes = 0x0200
	PInvokeAttributes_CallConvStdcall     PInvokeAttributes = 0x0300
	PInvokeAttributes_CallConvThiscall    PInvokeAttributes = 0x0400
	PInvokeAttributes_CallConvFastcall    PInvokeAttributes = 0x0500
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

const (
	ManifestResourceAttributes_VisibilityMask ManifestResourceAttributes = 0x0007
	ManifestResourceAttributes_Public         ManifestResourceAttributes = 0x0001
	ManifestResourceAttributes_Private        ManifestResourceAttributes = 0x0002
)

// ManifestResource is defined in §II.22.24.
// @table=0x28
type ManifestResource struct {
	Offset         uint32
	Flags          ManifestResourceAttributes
	Name           String
	Implementation CodedIndex[Implementation]
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
	MethodAttributes_MemberAccessMask   MethodAttributes = 0x0007
	MethodAttributes_CompilerControlled MethodAttributes = 0x0000
	MethodAttributes_Private            MethodAttributes = 0x0001
	MethodAttributes_FamANDAssem        MethodAttributes = 0x0002
	MethodAttributes_Assem              MethodAttributes = 0x0003
	MethodAttributes_Family             MethodAttributes = 0x0004
	MethodAttributes_FamORAssem         MethodAttributes = 0x0005
	MethodAttributes_Public             MethodAttributes = 0x0006
	MethodAttributes_Static             MethodAttributes = 0x0010
	MethodAttributes_Final              MethodAttributes = 0x0020
	MethodAttributes_Virtual            MethodAttributes = 0x0040
	MethodAttributes_HideBySig          MethodAttributes = 0x0080
	MethodAttributes_VtableLayoutMask   MethodAttributes = 0x0100
	MethodAttributes_ReuseSlot          MethodAttributes = 0x0000
	MethodAttributes_NewSlot            MethodAttributes = 0x0100
	MethodAttributes_Strict             MethodAttributes = 0x0200
	MethodAttributes_Abstract           MethodAttributes = 0x0400
	MethodAttributes_SpecialName        MethodAttributes = 0x0800
	MethodAttributes_PInvokeImpl        MethodAttributes = 0x2000
	MethodAttributes_UnmanagedExport    MethodAttributes = 0x0008
	MethodAttributes_RTSpecialName      MethodAttributes = 0x1000
	MethodAttributes_HasSecurity        MethodAttributes = 0x4000
	MethodAttributes_RequireSecObject   MethodAttributes = 0x8000
)

// MethodImplAttributes is defined in §II.23.1.11.
type MethodImplAttributes uint16

const (
	MethodImplAttributes_CodeTypeMask     MethodImplAttributes = 0x0003
	MethodImplAttributes_IL               MethodImplAttributes = 0x0000
	MethodImplAttributes_Native           MethodImplAttributes = 0x0001
	MethodImplAttributes_OPTIL            MethodImplAttributes = 0x0002
	MethodImplAttributes_Runtime          MethodImplAttributes = 0x0003
	MethodImplAttributes_ManagedMask      MethodImplAttributes = 0x0004
	MethodImplAttributes_Unmanaged        MethodImplAttributes = 0x0004
	MethodImplAttributes_Managed          MethodImplAttributes = 0x0000
	MethodImplAttributes_ForwardRef       MethodImplAttributes = 0x0010
	MethodImplAttributes_PreserveSig      MethodImplAttributes = 0x0080
	MethodImplAttributes_InternalCall     MethodImplAttributes = 0x1000
	MethodImplAttributes_Synchronized     MethodImplAttributes = 0x0020
	MethodImplAttributes_NoInlining       MethodImplAttributes = 0x0008
	MethodImplAttributes_MaxMethodImplVal MethodImplAttributes = 0xffff
	MethodImplAttributes_NoOptimization   MethodImplAttributes = 0x0040
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
	Instantiation []byte
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
	ParamAttributes_Unused          ParamAttributes = 0xcfe0
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
	PropertyAttributes_Unused        PropertyAttributes = 0xe9ff
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
type TypeAttributes uint32

const (
	TypeAttributes_VisibilityMask         TypeAttributes = 0x00000007
	TypeAttributes_NotPublic              TypeAttributes = 0x00000000
	TypeAttributes_Public                 TypeAttributes = 0x00000001
	TypeAttributes_NestedPublic           TypeAttributes = 0x00000002
	TypeAttributes_NestedPrivate          TypeAttributes = 0x00000003
	TypeAttributes_NestedFamily           TypeAttributes = 0x00000004
	TypeAttributes_NestedAssembly         TypeAttributes = 0x00000005
	TypeAttributes_NestedFamANDAssem      TypeAttributes = 0x00000006
	TypeAttributes_NestedFamORAssem       TypeAttributes = 0x00000007
	TypeAttributes_LayoutMask             TypeAttributes = 0x00000018
	TypeAttributes_AutoLayout             TypeAttributes = 0x00000000
	TypeAttributes_SequentialLayout       TypeAttributes = 0x00000008
	TypeAttributes_ExplicitLayout         TypeAttributes = 0x00000010
	TypeAttributes_ClassSemanticsMask     TypeAttributes = 0x00000020
	TypeAttributes_Class                  TypeAttributes = 0x00000000
	TypeAttributes_Interface              TypeAttributes = 0x00000020
	TypeAttributes_Abstract               TypeAttributes = 0x00000080
	TypeAttributes_Sealed                 TypeAttributes = 0x00000100
	TypeAttributes_SpecialName            TypeAttributes = 0x00000400
	TypeAttributes_Import                 TypeAttributes = 0x00001000
	TypeAttributes_Serializable           TypeAttributes = 0x00002000
	TypeAttributes_StringFormatMask       TypeAttributes = 0x00030000
	TypeAttributes_AnsiClass              TypeAttributes = 0x00000000
	TypeAttributes_UnicodeClass           TypeAttributes = 0x00010000
	TypeAttributes_AutoClass              TypeAttributes = 0x00020000
	TypeAttributes_CustomFormatClass      TypeAttributes = 0x00030000
	TypeAttributes_CustomStringFormatMask TypeAttributes = 0x00C00000
	TypeAttributes_BeforeFieldInit        TypeAttributes = 0x00100000
	TypeAttributes_RTSpecialName          TypeAttributes = 0x00000800
	TypeAttributes_HasSecurity            TypeAttributes = 0x00040000
	TypeAttributes_IsTypeForwarder        TypeAttributes = 0x00200000
)

// TypeDef is defined in §II.22.37.
// @table=0x02
type TypeDef struct {
	Flags      TypeAttributes
	Name       String
	Namespace  String
	Extends    CodedIndex[TypeDefOrRef]
	FieldList  Slice // @ref=Field
	MethodList Slice // @ref=MethodDef
}

// TypeRef is defined in §II.22.38.
// @table=0x01
type TypeRef struct {
	ResolutionScope CodedIndex[ResolutionScope]
	Name            String
	Namespace       String
}

// TypeSpec is defined in §II.22.39.
// @table=0x1B
type TypeSpec struct {
	Signature []byte
}
