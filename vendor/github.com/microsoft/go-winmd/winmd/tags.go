// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

type CodedTag interface {
	TypeDefOrRef |
		HasConstant |
		HasFieldMarshal |
		HasDeclSecurity |
		MemberRefParent |
		HasSemantics |
		MethodDefOrRef |
		MemberForwarded |
		Implementation |
		CustomAttributeType |
		ResolutionScope |
		TypeOrMethodDef |
		HasCustomAttribute |
		TypeDefOrRefOrSpec
	kind() codedKind
	String() string
}

type TypeDefOrRef int8

func (TypeDefOrRef) kind() codedKind { return codedTypeDefOrRef }

const (
	// TypeDefOrRef_Null represents a null Extends or EventType, not a table tag.
	TypeDefOrRef_Null     TypeDefOrRef = -1
	TypeDefOrRef_TypeDef  TypeDefOrRef = 0
	TypeDefOrRef_TypeRef  TypeDefOrRef = 1
	TypeDefOrRef_TypeSpec TypeDefOrRef = 2
)

type HasConstant int8

func (HasConstant) kind() codedKind { return codedHasConstant }

const (
	HasConstant_Field    HasConstant = 0
	HasConstant_Param    HasConstant = 1
	HasConstant_Property HasConstant = 2
)

type HasFieldMarshal int8

func (HasFieldMarshal) kind() codedKind { return codedHasFieldMarshal }

const (
	HasFieldMarshal_Field HasFieldMarshal = 0
	HasFieldMarshal_Param HasFieldMarshal = 1
)

type HasDeclSecurity int8

func (HasDeclSecurity) kind() codedKind { return codedHasDeclSecurity }

const (
	HasDeclSecurity_TypeDef   HasDeclSecurity = 0
	HasDeclSecurity_MethodDef HasDeclSecurity = 1
	HasDeclSecurity_Assembly  HasDeclSecurity = 2
)

type MemberRefParent int8

func (MemberRefParent) kind() codedKind { return codedMemberRefParent }

const (
	MemberRefParent_TypeDef   MemberRefParent = 0
	MemberRefParent_TypeRef   MemberRefParent = 1
	MemberRefParent_ModuleRef MemberRefParent = 2
	MemberRefParent_MethodDef MemberRefParent = 3
	MemberRefParent_TypeSpec  MemberRefParent = 4
)

type HasSemantics int8

func (HasSemantics) kind() codedKind { return codedHasSemantics }

const (
	HasSemantics_Event    HasSemantics = 0
	HasSemantics_Property HasSemantics = 1
)

type MethodDefOrRef int8

func (MethodDefOrRef) kind() codedKind { return codedMethodDefOrRef }

const (
	MethodDefOrRef_MethodDef MethodDefOrRef = 0
	MethodDefOrRef_MemberRef MethodDefOrRef = 1
)

type MemberForwarded int8

func (MemberForwarded) kind() codedKind { return codedMemberForwarded }

const (
	MemberForwarded_Field     MemberForwarded = 0
	MemberForwarded_MethodDef MemberForwarded = 1
)

type Implementation int8

func (Implementation) kind() codedKind { return codedImplementation }

const (
	// Implementation_Null denotes a resource in the current file, not a table tag.
	Implementation_Null         Implementation = -1
	Implementation_File         Implementation = 0
	Implementation_AssemblyRef  Implementation = 1
	Implementation_ExportedType Implementation = 2
)

type CustomAttributeType int8

func (CustomAttributeType) kind() codedKind { return codedCustomAttributeType }

const (
	CustomAttributeType_Reserved0 CustomAttributeType = 0
	CustomAttributeType_Reserved1 CustomAttributeType = 1
	CustomAttributeType_MethodDef CustomAttributeType = 2
	CustomAttributeType_MemberRef CustomAttributeType = 3
	CustomAttributeType_Reserved4 CustomAttributeType = 4
)

type ResolutionScope int8

func (ResolutionScope) kind() codedKind { return codedResolutionScope }

const (
	// ResolutionScope_Null denotes resolution through ExportedType, not a table tag.
	ResolutionScope_Null        ResolutionScope = -1
	ResolutionScope_Module      ResolutionScope = 0
	ResolutionScope_ModuleRef   ResolutionScope = 1
	ResolutionScope_AssemblyRef ResolutionScope = 2
	ResolutionScope_TypeRef     ResolutionScope = 3
)

type TypeOrMethodDef int8

func (TypeOrMethodDef) kind() codedKind { return codedTypeOrMethodDef }

const (
	TypeOrMethodDef_TypeDef   TypeOrMethodDef = 0
	TypeOrMethodDef_MethodDef TypeOrMethodDef = 1
)

type HasCustomAttribute int8

func (HasCustomAttribute) kind() codedKind { return codedHasCustomAttribute }

const (
	HasCustomAttribute_MethodDef              HasCustomAttribute = 0
	HasCustomAttribute_Field                  HasCustomAttribute = 1
	HasCustomAttribute_TypeRef                HasCustomAttribute = 2
	HasCustomAttribute_TypeDef                HasCustomAttribute = 3
	HasCustomAttribute_Param                  HasCustomAttribute = 4
	HasCustomAttribute_InterfaceImpl          HasCustomAttribute = 5
	HasCustomAttribute_MemberRef              HasCustomAttribute = 6
	HasCustomAttribute_Module                 HasCustomAttribute = 7
	HasCustomAttribute_DeclSecurity           HasCustomAttribute = 8
	HasCustomAttribute_Property               HasCustomAttribute = 9
	HasCustomAttribute_Event                  HasCustomAttribute = 10
	HasCustomAttribute_StandAloneSig          HasCustomAttribute = 11
	HasCustomAttribute_ModuleRef              HasCustomAttribute = 12
	HasCustomAttribute_TypeSpec               HasCustomAttribute = 13
	HasCustomAttribute_Assembly               HasCustomAttribute = 14
	HasCustomAttribute_AssemblyRef            HasCustomAttribute = 15
	HasCustomAttribute_File                   HasCustomAttribute = 16
	HasCustomAttribute_ExportedType           HasCustomAttribute = 17
	HasCustomAttribute_ManifestResource       HasCustomAttribute = 18
	HasCustomAttribute_GenericParam           HasCustomAttribute = 19
	HasCustomAttribute_GenericParamConstraint HasCustomAttribute = 20
	HasCustomAttribute_MethodSpec             HasCustomAttribute = 21
)

type TypeDefOrRefOrSpec int8

func (TypeDefOrRefOrSpec) kind() codedKind { return codedTypeDefOrRefOrSpec }

const (
	TypeDefOrRefOrSpec_TypeDef  TypeDefOrRefOrSpec = 0
	TypeDefOrRefOrSpec_TypeRef  TypeDefOrRefOrSpec = 1
	TypeDefOrRefOrSpec_TypeSpec TypeDefOrRefOrSpec = 2
)

func codedFromInt8[T CodedTag](v int8) T {
	return T(v)
}
