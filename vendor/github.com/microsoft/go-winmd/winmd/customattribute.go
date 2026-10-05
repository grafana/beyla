// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// CustomAttributeArgumentType describes a serialized custom-attribute argument.
// Kind is a primitive ElementType, ElementType_STRING, ElementType_TYPE for
// System.Type, ElementType_BOXED_OBJECT for System.Object, ElementType_ENUM,
// or ElementType_SZARRAY. Signature types such as ElementType_CLASS and
// ElementType_VALUETYPE must first be resolved to these serialization types.
type CustomAttributeArgumentType struct {
	Kind ElementType
	// Enum and EnumUnderlyingType describe an enum and its underlying integer type.
	Enum               EnumReference
	EnumUnderlyingType ElementType
	// Element describes an SZARRAY's element type. Directly nested arrays are
	// not supported by the custom-attribute format, but object arrays can contain
	// boxed arrays.
	Element *CustomAttributeArgumentType
}

// CustomAttributeArgument is a typed fixed, named, boxed, or array argument.
type CustomAttributeArgument struct {
	Type CustomAttributeArgumentType
	// Value uses the primitive Go types returned by [DecodeConstant]. Strings and
	// System.Type names are strings, or nil for null. Enums use the Go representation
	// of their underlying type. Arrays are []CustomAttributeArgument, or nil for null;
	// an empty array is a non-nil empty slice. Boxed values are represented by
	// another CustomAttributeArgument so their actual type is preserved.
	Value any
}

// CustomAttributeNamedArgument identifies a named field or property argument.
type CustomAttributeNamedArgument struct {
	Kind ElementType // ElementType_FIELD or ElementType_PROPERTY
	Name string
	CustomAttributeArgument
}

// CustomAttributeValue contains the arguments serialized in a CustomAttribute.
// Arguments are kept in metadata order; named fields and properties with the
// same name remain distinct. Argument and value data is independent of the
// input blob and belongs to this result, except for read-only [EnumReference]
// data, which may be shared with the decoder and other results.
type CustomAttributeValue struct {
	FixedArguments []CustomAttributeArgument
	NamedArguments []CustomAttributeNamedArgument
}

// decodeCustomAttributeValue decodes an entire custom-attribute value blob according
// to ECMA-335 §II.23.3. fixedTypes must describe the constructor's parameters in
// declaration order: their types and count are not encoded in the value blob.
// CustomAttributeDecoder resolves them from metadata constructor signatures.
//
// resolveEnum supplies the underlying integer type of enum references in the blob
// or in fixedTypes. It may be nil if all fixed enums specify EnumUnderlyingType
// and no serialized argument type requires enum resolution. Serialized enum names
// are passed unchanged. Strings and System.Type names use SerString, not the
// UTF-16 encoding used by Constant. Array counts are four-byte little-endian
// integers, with 0xffffffff representing null.
//
// An empty blob is accepted only when there are no fixed arguments. Otherwise,
// the prolog, all arguments, and the named-argument count must be present, and
// trailing bytes are rejected. Errors return a zero CustomAttributeValue;
// truncation errors wrap io.ErrUnexpectedEOF. Type and value nesting is limited
// to 64 levels. The decoder does not check member accessibility or assignability.
func decodeCustomAttributeValue(data []byte, fixedTypes []CustomAttributeArgumentType, resolveEnum func(EnumReference) (ElementType, error)) (CustomAttributeValue, error) {
	r := customAttributeReader{data: data, resolveEnum: resolveEnum}
	if len(data) == 0 && len(fixedTypes) == 0 {
		return CustomAttributeValue{}, nil
	}
	if prolog := r.uint16(); r.err != nil {
		return CustomAttributeValue{}, r.err
	} else if prolog != 1 {
		return CustomAttributeValue{}, errors.New("invalid custom attribute prolog")
	}
	var result CustomAttributeValue
	for i, typ := range fixedTypes {
		typ = r.normalizeType(typ, 0)
		value := r.value(typ, 0)
		if r.err != nil {
			return CustomAttributeValue{}, fmt.Errorf("fixed argument %d: %w", i, r.err)
		}
		result.FixedArguments = append(result.FixedArguments, CustomAttributeArgument{Type: typ, Value: value})
	}
	count := r.uint16()
	for i := range count {
		kind := ElementType(r.byte())
		if r.err == nil && kind != ElementType_FIELD && kind != ElementType_PROPERTY {
			r.err = fmt.Errorf("invalid named argument kind %v", kind)
		}
		typ := r.argumentType(0)
		name := r.name()
		value := r.value(typ, 0)
		if r.err != nil {
			return CustomAttributeValue{}, fmt.Errorf("named argument %d: %w", i, r.err)
		}
		result.NamedArguments = append(result.NamedArguments, CustomAttributeNamedArgument{
			Kind: kind,
			Name: name,
			CustomAttributeArgument: CustomAttributeArgument{
				Type:  typ,
				Value: value,
			},
		})
	}
	if r.err != nil {
		return CustomAttributeValue{}, r.err
	}
	if len(r.data) != 0 {
		return CustomAttributeValue{}, errors.New("trailing custom attribute data")
	}
	return result, nil
}

const maxCustomAttributeDepth = 64

type customAttributeReader struct {
	data        []byte
	err         error
	resolveEnum func(EnumReference) (ElementType, error)
	enums       map[string]ElementType
}

func (r *customAttributeReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.data) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	data := r.data[:n:n]
	r.data = r.data[n:]
	return data
}

func (r *customAttributeReader) byte() byte {
	if data := r.take(1); data != nil {
		return data[0]
	}
	return 0
}

func (r *customAttributeReader) uint16() uint16 {
	if data := r.take(2); data != nil {
		return binary.LittleEndian.Uint16(data)
	}
	return 0
}

func (r *customAttributeReader) uint32() uint32 {
	if data := r.take(4); data != nil {
		return binary.LittleEndian.Uint32(data)
	}
	return 0
}

func (r *customAttributeReader) compressedUint32() uint32 {
	if r.err != nil {
		return 0
	}
	value, n, err := DecodeCompressedUint32(r.data)
	if err != nil {
		r.err = err
		return 0
	}
	r.data = r.data[n:]
	return value
}

func (r *customAttributeReader) serString() []byte {
	if r.err != nil {
		return nil
	}
	value, n, err := DecodeSerString(r.data)
	if err != nil {
		r.err = err
		return nil
	}
	r.data = r.data[n:]
	return value
}

func (r *customAttributeReader) name() string {
	value := r.serString()
	if r.err == nil && len(value) == 0 {
		r.err = errors.New("null or empty custom attribute name")
	}
	return string(value)
}

func (r *customAttributeReader) checkDepth(depth int) bool {
	if r.err != nil {
		return false
	}
	if depth >= maxCustomAttributeDepth {
		r.err = errors.New("custom attribute nesting limit exceeded")
		return false
	}
	return true
}

func (r *customAttributeReader) normalizeType(typ CustomAttributeArgumentType, depth int) CustomAttributeArgumentType {
	if !r.checkDepth(depth) {
		return typ
	}
	switch typ.Kind {
	case ElementType_BOOLEAN, ElementType_CHAR,
		ElementType_I1, ElementType_U1, ElementType_I2, ElementType_U2,
		ElementType_I4, ElementType_U4, ElementType_I8, ElementType_U8,
		ElementType_R4, ElementType_R8, ElementType_STRING,
		ElementType_TYPE, ElementType_BOXED_OBJECT:
	case ElementType_ENUM:
		ref := typ.Enum
		if ref.Metadata == nil && ref.SerializedName == "" || ref.Metadata != nil && (ref.Metadata.Name == "" || ref.SerializedName != "") {
			r.err = errors.New("invalid custom attribute enum reference")
			break
		}
		if typ.EnumUnderlyingType == 0 {
			if ref.Metadata == nil {
				typ.EnumUnderlyingType = r.enums[ref.SerializedName]
			}
			if typ.EnumUnderlyingType == 0 {
				if r.resolveEnum == nil {
					r.err = &UnresolvedEnumError{Reference: ref}
					break
				}
				typ.EnumUnderlyingType, r.err = r.resolveEnum(ref)
				if r.err != nil {
					r.err = fmt.Errorf("resolve enum %q: %w", ref.name(), r.err)
					break
				}
			}
		}
		if !isCustomAttributeEnumType(typ.EnumUnderlyingType) {
			r.err = fmt.Errorf("unsupported underlying type %v for enum %q", typ.EnumUnderlyingType, ref.name())
			break
		}
		// Metadata enums are already resolved by handle. Never let a fixed
		// metadata argument populate the cache for serialized enum names.
		if ref.Metadata == nil {
			if r.enums == nil {
				r.enums = make(map[string]ElementType)
			}
			r.enums[ref.SerializedName] = typ.EnumUnderlyingType
		}
	case ElementType_SZARRAY:
		if typ.Element == nil || typ.Element.Kind == ElementType_SZARRAY {
			r.err = errors.New("invalid custom attribute array element type")
			break
		}
		element := r.normalizeType(*typ.Element, depth+1)
		typ.Element = &element
	default:
		r.err = fmt.Errorf("unsupported custom attribute type %v", typ.Kind)
	}
	return typ
}

func isCustomAttributeEnumType(typ ElementType) bool {
	return typ >= ElementType_BOOLEAN && typ <= ElementType_U8
}

func (r *customAttributeReader) argumentType(depth int) CustomAttributeArgumentType {
	if !r.checkDepth(depth) {
		return CustomAttributeArgumentType{}
	}
	typ := CustomAttributeArgumentType{Kind: ElementType(r.byte())}
	switch typ.Kind {
	case ElementType_ENUM:
		typ.Enum = EnumReference{SerializedName: r.name()}
	case ElementType_SZARRAY:
		element := r.argumentType(depth + 1)
		typ.Element = &element
	}
	return r.normalizeType(typ, depth)
}

func (r *customAttributeReader) value(typ CustomAttributeArgumentType, depth int) any {
	if !r.checkDepth(depth) {
		return nil
	}
	switch typ.Kind {
	case ElementType_STRING, ElementType_TYPE:
		if value := r.serString(); value != nil {
			return string(value)
		}
		return nil
	case ElementType_BOXED_OBJECT:
		// The serialized type tag is required, including for null values such
		// as STRING followed by the SerString null marker 0xff.
		boxedType := r.argumentType(depth + 1)
		if r.err == nil && boxedType.Kind == ElementType_BOXED_OBJECT {
			r.err = errors.New("invalid boxed custom attribute type")
		}
		return CustomAttributeArgument{Type: boxedType, Value: r.value(boxedType, depth+1)}
	case ElementType_SZARRAY:
		count := r.uint32()
		if r.err != nil || count == math.MaxUint32 {
			return nil
		}
		if count > math.MaxInt32 {
			r.err = errors.New("invalid custom attribute array length")
			return nil
		}
		// Every element consumes at least one byte. Check before allocating, and
		// grow incrementally rather than trusting a count from malformed input.
		if uint64(count) > uint64(len(r.data)) {
			r.err = io.ErrUnexpectedEOF
			return nil
		}
		values := make([]CustomAttributeArgument, 0, min(int(count), 1024))
		for i := range count {
			value := r.value(*typ.Element, depth+1)
			if r.err != nil {
				r.err = fmt.Errorf("array element %d: %w", i, r.err)
				return nil
			}
			values = append(values, CustomAttributeArgument{Type: *typ.Element, Value: value})
		}
		return values
	case ElementType_ENUM:
		return r.value(CustomAttributeArgumentType{Kind: typ.EnumUnderlyingType}, depth+1)
	}
	var size int
	switch typ.Kind {
	case ElementType_BOOLEAN, ElementType_I1, ElementType_U1:
		size = 1
	case ElementType_CHAR, ElementType_I2, ElementType_U2:
		size = 2
	case ElementType_I4, ElementType_U4, ElementType_R4:
		size = 4
	case ElementType_I8, ElementType_U8, ElementType_R8:
		size = 8
	default:
		r.err = fmt.Errorf("unsupported custom attribute type %v", typ.Kind)
		return nil
	}
	data := r.take(size)
	if r.err != nil {
		return nil
	}
	if typ.Kind == ElementType_BOOLEAN && data[0] > 1 {
		r.err = errors.New("invalid custom attribute Boolean value")
		return nil
	}
	value, err := DecodeConstant(typ.Kind, data)
	r.err = err
	return value
}
