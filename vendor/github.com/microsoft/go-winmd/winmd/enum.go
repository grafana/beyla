// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"errors"
	"fmt"
	"io"
)

// EnumUnderlyingType returns the underlying type of the enum TypeDef at index,
// as defined in ECMA-335 §II.14.3. The definition must directly extend System.Enum
// through a TypeDef or TypeRef and contain exactly one instance field, regardless
// of its name.
//
// The result is ElementType_BOOLEAN, ElementType_CHAR, one of ElementType_I1
// through ElementType_U8, ElementType_I, or ElementType_U. Custom modifiers on
// the instance field are skipped after validating their type handles.
// On error, the result is zero. Truncated field signatures wrap io.ErrUnexpectedEOF.
func (m *Metadata) EnumUnderlyingType(index Index) (ElementType, error) {
	def, err := m.Tables.TypeDef.At(index)
	if err != nil {
		return 0, err
	}
	var namespace, name String
	var nested bool
	switch def.Extends.Tag {
	case TypeDefOrRef_TypeDef:
		base, err := m.Tables.TypeDef.At(def.Extends.Index)
		if err != nil {
			return 0, err
		}
		namespace, name = base.Namespace, base.Name
		nested = base.Flags.Visibility().IsNested()
	case TypeDefOrRef_TypeRef:
		base, err := m.Tables.TypeRef.At(def.Extends.Index)
		if err != nil {
			return 0, err
		}
		namespace, name = base.Namespace, base.Name
		nested = base.ResolutionScope.Tag == ResolutionScope_TypeRef
	default:
		return 0, fmt.Errorf("TypeDef %d is not an enum", index)
	}
	if nested || namespace.String() != "System" || name.String() != "Enum" {
		return 0, fmt.Errorf("TypeDef %d does not extend System.Enum", index)
	}

	var underlying ElementType
	for fieldIndex := range def.FieldList.All() {
		field, err := m.Tables.Field.At(fieldIndex)
		if err != nil {
			return 0, err
		}
		if field.Flags.HasAll(FieldFlags_Static) {
			continue
		}
		if underlying != 0 {
			return 0, fmt.Errorf("multiple instance fields for enum TypeDef %d", index)
		}
		underlying, err = m.enumFieldType(field.Signature)
		if err != nil {
			return 0, fmt.Errorf("enum TypeDef %d field %d: %w", index, fieldIndex, err)
		}
	}
	if underlying == 0 {
		return 0, fmt.Errorf("no instance field for enum TypeDef %d", index)
	}
	return underlying, nil
}

func (m *Metadata) enumFieldType(data SigFieldBlob) (ElementType, error) {
	if len(data) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if data[0] != sigKind_FIELD {
		return 0, errors.New("invalid enum underlying field signature")
	}
	data = data[1:]
	for {
		if len(data) == 0 {
			return 0, io.ErrUnexpectedEOF
		}
		kind := ElementType(data[0])
		data = data[1:]
		if kind != ElementType_CMOD_OPT && kind != ElementType_CMOD_REQD {
			if !isEnumUnderlyingType(kind) || len(data) != 0 {
				return 0, errors.New("invalid enum underlying field type")
			}
			return kind, nil
		}
		code, n, err := DecodeCompressedUint32(data)
		if err != nil {
			return 0, err
		}
		mod, err := parseCoded[TypeDefOrRefOrSpec](code)
		if err != nil {
			return 0, err
		}
		var count uint32
		switch mod.Tag {
		case TypeDefOrRefOrSpec_TypeDef:
			count = m.Tables.TypeDef.Len()
		case TypeDefOrRefOrSpec_TypeRef:
			count = m.Tables.TypeRef.Len()
		case TypeDefOrRefOrSpec_TypeSpec:
			count = m.Tables.TypeSpec.Len()
		default:
			return 0, errors.New("invalid enum field modifier type handle")
		}
		if uint32(mod.Index) >= count {
			return 0, errors.New("enum field modifier type handle is out of range")
		}
		data = data[n:]
	}
}

func isEnumUnderlyingType(typ ElementType) bool {
	return typ >= ElementType_BOOLEAN && typ <= ElementType_U8 || typ == ElementType_I || typ == ElementType_U
}
