// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import "fmt"

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
}

type TypeDefOrRef struct{ int8 }

func (TypeDefOrRef) kind() codedKind { return codedTypeDefOrRef }

var (
	TypeDefOrRef_Null     = TypeDefOrRef{-1}
	TypeDefOrRef_TypeDef  = TypeDefOrRef{0}
	TypeDefOrRef_TypeRef  = TypeDefOrRef{1}
	TypeDefOrRef_TypeSpec = TypeDefOrRef{2}
)

type HasConstant struct{ int8 }

func (HasConstant) kind() codedKind { return codedHasConstant }

var (
	HasConstant_Null     = HasConstant{-1}
	HasConstant_Field    = HasConstant{0}
	HasConstant_Param    = HasConstant{1}
	HasConstant_Property = HasConstant{2}
)

type HasFieldMarshal struct{ int8 }

func (HasFieldMarshal) kind() codedKind { return codedHasFieldMarshal }

var (
	HasFieldMarshal_Null  = HasFieldMarshal{-1}
	HasFieldMarshal_Field = HasFieldMarshal{0}
	HasFieldMarshal_Param = HasFieldMarshal{1}
)

type HasDeclSecurity struct{ int8 }

func (HasDeclSecurity) kind() codedKind { return codedHasDeclSecurity }

var (
	HasDeclSecurity_Null      = HasDeclSecurity{-1}
	HasDeclSecurity_TypeDef   = HasDeclSecurity{0}
	HasDeclSecurity_MethodDef = HasDeclSecurity{1}
	HasDeclSecurity_Assembly  = HasDeclSecurity{2}
)

type MemberRefParent struct{ int8 }

func (MemberRefParent) kind() codedKind { return codedMemberRefParent }

var (
	MemberRefParent_Null      = MemberRefParent{-1}
	MemberRefParent_TypeDef   = MemberRefParent{0}
	MemberRefParent_TypeRef   = MemberRefParent{1}
	MemberRefParent_ModuleRef = MemberRefParent{2}
	MemberRefParent_MethodDef = MemberRefParent{3}
	MemberRefParent_TypeSpec  = MemberRefParent{4}
)

type HasSemantics struct{ int8 }

func (HasSemantics) kind() codedKind { return codedHasSemantics }

var (
	HasSemantics_Null     = HasSemantics{-1}
	HasSemantics_Event    = HasSemantics{0}
	HasSemantics_Property = HasSemantics{1}
)

type MethodDefOrRef struct{ int8 }

func (MethodDefOrRef) kind() codedKind { return codedMethodDefOrRef }

var (
	MethodDefOrRef_Null      = MethodDefOrRef{-1}
	MethodDefOrRef_MethodDef = MethodDefOrRef{0}
	MethodDefOrRef_MemberRef = MethodDefOrRef{1}
)

type MemberForwarded struct{ int8 }

func (MemberForwarded) kind() codedKind { return codedMemberForwarded }

var (
	MemberForwarded_Null      = MemberForwarded{-1}
	MemberForwarded_Field     = MemberForwarded{0}
	MemberForwarded_MethodDef = MemberForwarded{1}
)

type Implementation struct{ int8 }

func (Implementation) kind() codedKind { return codedImplementation }

var (
	Implementation_Null         = Implementation{-1}
	Implementation_File         = Implementation{0}
	Implementation_AssemblyRef  = Implementation{1}
	Implementation_ExportedType = Implementation{2}
)

type CustomAttributeType struct{ int8 }

func (CustomAttributeType) kind() codedKind { return codedCustomAttributeType }

var (
	CustomAttributeType_Null      = CustomAttributeType{-1}
	CustomAttributeType_Reserved0 = CustomAttributeType{0}
	CustomAttributeType_Reserved1 = CustomAttributeType{1}
	CustomAttributeType_MethodDef = CustomAttributeType{2}
	CustomAttributeType_MemberRef = CustomAttributeType{3}
	CustomAttributeType_Reserved4 = CustomAttributeType{4}
)

type ResolutionScope struct{ int8 }

func (ResolutionScope) kind() codedKind { return codedResolutionScope }

var (
	ResolutionScope_Null        = ResolutionScope{-1}
	ResolutionScope_Module      = ResolutionScope{0}
	ResolutionScope_ModuleRef   = ResolutionScope{1}
	ResolutionScope_AssemblyRef = ResolutionScope{2}
	ResolutionScope_TypeRef     = ResolutionScope{3}
)

type TypeOrMethodDef struct{ int8 }

func (TypeOrMethodDef) kind() codedKind { return codedTypeOrMethodDef }

var (
	TypeOrMethodDef_Null      = TypeOrMethodDef{-1}
	TypeOrMethodDef_TypeDef   = TypeOrMethodDef{0}
	TypeOrMethodDef_MethodDef = TypeOrMethodDef{1}
)

type HasCustomAttribute struct{ int8 }

func (HasCustomAttribute) kind() codedKind { return codedHasCustomAttribute }

var (
	HasCustomAttribute_Null                   = HasCustomAttribute{-1}
	HasCustomAttribute_MethodDef              = HasCustomAttribute{0}
	HasCustomAttribute_Field                  = HasCustomAttribute{1}
	HasCustomAttribute_TypeRef                = HasCustomAttribute{2}
	HasCustomAttribute_TypeDef                = HasCustomAttribute{3}
	HasCustomAttribute_Param                  = HasCustomAttribute{4}
	HasCustomAttribute_InterfaceImpl          = HasCustomAttribute{5}
	HasCustomAttribute_MemberRef              = HasCustomAttribute{6}
	HasCustomAttribute_Module                 = HasCustomAttribute{7}
	HasCustomAttribute_None                   = HasCustomAttribute{8}
	HasCustomAttribute_Property               = HasCustomAttribute{9}
	HasCustomAttribute_Event                  = HasCustomAttribute{10}
	HasCustomAttribute_StandAloneSig          = HasCustomAttribute{11}
	HasCustomAttribute_ModuleRef              = HasCustomAttribute{12}
	HasCustomAttribute_TypeSpec               = HasCustomAttribute{13}
	HasCustomAttribute_Assembly               = HasCustomAttribute{14}
	HasCustomAttribute_AssemblyRef            = HasCustomAttribute{15}
	HasCustomAttribute_File                   = HasCustomAttribute{16}
	HasCustomAttribute_ExportedType           = HasCustomAttribute{17}
	HasCustomAttribute_ManifestResource       = HasCustomAttribute{18}
	HasCustomAttribute_GenericParam           = HasCustomAttribute{19}
	HasCustomAttribute_GenericParamConstraint = HasCustomAttribute{20}
	HasCustomAttribute_MethodSpec             = HasCustomAttribute{21}
)

type TypeDefOrRefOrSpec struct{ int8 }

func (TypeDefOrRefOrSpec) kind() codedKind { return codedTypeDefOrRefOrSpec }

var (
	TypeDefOrRefOrSpec_Null     = TypeDefOrRefOrSpec{-1}
	TypeDefOrRefOrSpec_TypeDef  = TypeDefOrRefOrSpec{0}
	TypeDefOrRefOrSpec_TypeRef  = TypeDefOrRefOrSpec{1}
	TypeDefOrRefOrSpec_TypeSpec = TypeDefOrRefOrSpec{2}
)

func codedFromInt8[T CodedTag](v int8) T {
	var zero T
	switch tag := any(&zero).(type) {
	case *TypeDefOrRef:
		tag.int8 = v
	case *HasConstant:
		tag.int8 = v
	case *HasFieldMarshal:
		tag.int8 = v
	case *HasDeclSecurity:
		tag.int8 = v
	case *MemberRefParent:
		tag.int8 = v
	case *HasSemantics:
		tag.int8 = v
	case *MethodDefOrRef:
		tag.int8 = v
	case *MemberForwarded:
		tag.int8 = v
	case *Implementation:
		tag.int8 = v
	case *CustomAttributeType:
		tag.int8 = v
	case *ResolutionScope:
		tag.int8 = v
	case *TypeOrMethodDef:
		tag.int8 = v
	case *HasCustomAttribute:
		tag.int8 = v
	case *TypeDefOrRefOrSpec:
		tag.int8 = v
	default:
		panic(fmt.Sprintf("unsupported coded tag type %T", zero))
	}
	return zero
}
