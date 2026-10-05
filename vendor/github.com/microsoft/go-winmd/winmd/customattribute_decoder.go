// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// EnumReference identifies an enum from either a constructor signature or a
// serialized attribute value. Exactly one of Metadata and SerializedName is set.
// References and their nested data are read-only and may be shared by decoded
// arguments, resolver calls, and the decoder's caches.
type EnumReference struct {
	// Metadata is set for a TypeDef or TypeRef in a constructor signature.
	Metadata *EnumReferenceMetadata
	// SerializedName is the original name from a named or boxed enum value.
	// It may be assembly-qualified and contain reflection type-name escapes.
	// No metadata reference is inferred from this string, even if resolved locally.
	SerializedName string
}

// EnumReferenceMetadata preserves the identity of a type referenced by metadata.
// Names are unescaped metadata strings, not a synthesized assembly-qualified name.
type EnumReferenceMetadata struct {
	// Handle identifies the TypeDef or TypeRef in the decoder's Metadata.
	Handle CodedIndex[TypeDefOrRefOrSpec]
	// Namespace is the namespace of the outermost type.
	Namespace string
	// Name is the enum's simple name.
	Name string
	// DeclaringTypes contains enclosing simple names, outermost first.
	DeclaringTypes []string
	// Assembly is the original AssemblyRef row for an external reference,
	// or nil for a definition or reference in the current module. Its flags,
	// culture, public key/token, and other fields are unchanged; heap data is shared.
	Assembly *AssemblyRef
}

// name is for local serialized-name lookup and diagnostics, never cache identity.
func (ref EnumReference) name() string {
	if ref.Metadata != nil {
		return ref.Metadata.fullName()
	}
	return ref.SerializedName
}

func (ref *EnumReferenceMetadata) fullName() string {
	var name strings.Builder
	if ref.Namespace != "" {
		name.WriteString(typeNameEscaper.Replace(ref.Namespace))
		name.WriteByte('.')
	}
	for _, declaring := range ref.DeclaringTypes {
		name.WriteString(typeNameEscaper.Replace(declaring))
		name.WriteByte('+')
	}
	name.WriteString(typeNameEscaper.Replace(ref.Name))
	return name.String()
}

// metadataTypeIdentity keeps raw metadata name boundaries separate from the
// reflection names used to resolve serialized enum references.
type metadataTypeIdentity struct {
	namespace string
	name      string
	// Metadata identifiers cannot contain NUL, so each enclosing name is
	// terminated with NUL to preserve nesting boundaries without escaping.
	declaringTypes string
}

func (ref *EnumReferenceMetadata) identity() metadataTypeIdentity {
	var declaringTypes string
	if len(ref.DeclaringTypes) != 0 {
		declaringTypes = strings.Join(ref.DeclaringTypes, "\x00") + "\x00"
	}
	return metadataTypeIdentity{namespace: ref.Namespace, name: ref.Name, declaringTypes: declaringTypes}
}

// UnresolvedEnumError reports a custom-attribute enum whose underlying integer
// type could not be resolved. Use [errors.As] to distinguish this condition from
// malformed metadata and report or skip the attribute without stopping other work.
type UnresolvedEnumError struct {
	Reference EnumReference
}

func (e *UnresolvedEnumError) Error() string {
	if ref := e.Reference.Metadata; ref != nil && ref.Assembly != nil {
		return fmt.Sprintf("cannot resolve custom attribute enum %q in assembly %q", ref.fullName(), ref.Assembly.Name)
	}
	return fmt.Sprintf("cannot resolve custom attribute enum %q", e.Reference.name())
}

// CustomAttributeDecoder resolves constructor signatures and enum types before
// decoding custom-attribute values. It caches metadata lookups for repeated use.
// Type definitions and references are limited to 64 levels of nesting.
// A decoder must not be used concurrently, and its metadata and
// [CustomAttributeDecoder.ResolveEnum] callback must not be changed after
// decoding starts. Separate decoders may share the same read-only [Metadata];
// shared callbacks must support any concurrent calls they receive.
type CustomAttributeDecoder struct {
	// ResolveEnum supplies the underlying integer type of enums not resolved
	// in the current metadata. The reference contains either raw metadata identity
	// or the original serialized type name, without assembly-name formatting or
	// public-key token computation. The reference must not be modified. Return an
	// *UnresolvedEnumError when an enum's underlying type is unavailable; other
	// errors are propagated without being classified as unresolved enums.
	// A nil callback reports unresolved enums with *UnresolvedEnumError.
	// The decoder never assumes an enum's size.
	// Enum arguments support ElementType_BOOLEAN, ElementType_CHAR, and the
	// fixed-width integer types ElementType_I1 through ElementType_U8. Native-sized
	// enum arguments are unsupported because their serialized width is unknown.
	ResolveEnum func(EnumReference) (ElementType, error)

	metadata               *Metadata
	constructors           map[CodedIndex[CustomAttributeType]][]CustomAttributeArgumentType
	enumsByType            map[CodedIndex[TypeDefOrRefOrSpec]]ElementType
	enumsByName            map[string]ElementType
	typeReferences         map[CodedIndex[TypeDefOrRefOrSpec]]*EnumReferenceMetadata
	typeParents            map[Index]Index
	parentsIndexed         bool
	parentsError           error
	typesByName            map[string]Index
	typesByIdentity        map[metadataTypeIdentity]Index
	typeNameDuplicates     map[string][]Index
	typeIdentityDuplicates map[Index][]Index
	typesIndexed           bool
	typesError             error
}

// NewCustomAttributeDecoder creates a reusable decoder for attributes in m.
// It resolves enums declared in m, including nested enums. Metadata references
// and serialized names are cached separately, by handle and original name.
// Unqualified serialized names and names qualified with m's simple assembly name
// can be resolved locally; other references are passed unchanged to
// [CustomAttributeDecoder.ResolveEnum].
func NewCustomAttributeDecoder(m *Metadata) *CustomAttributeDecoder {
	return &CustomAttributeDecoder{
		metadata:       m,
		constructors:   make(map[CodedIndex[CustomAttributeType]][]CustomAttributeArgumentType),
		enumsByType:    make(map[CodedIndex[TypeDefOrRefOrSpec]]ElementType),
		enumsByName:    make(map[string]ElementType),
		typeReferences: make(map[CodedIndex[TypeDefOrRefOrSpec]]*EnumReferenceMetadata),
	}
}

// Decode reads a's MethodDef or MemberRef constructor signature and decodes its
// value. Constructor signatures must be non-generic instance constructors with
// a void return type and valid custom-attribute parameter types. External enums
// require [CustomAttributeDecoder.ResolveEnum]; unsupported TypeSpec parameters
// are reported as errors.
// The input is not modified and must remain unchanged during the call. Returned
// argument and value data is independently owned, except for the read-only
// [EnumReference] data described in [CustomAttributeValue].
//
// Any error returns a zero CustomAttributeValue, not partial arguments.
// Use [errors.As] to detect *UnresolvedEnumError when an enum cannot be resolved.
// The original a.Value can be retained for later decoding.
func (d *CustomAttributeDecoder) Decode(a CustomAttribute) (CustomAttributeValue, error) {
	if d == nil || d.metadata == nil || d.metadata.Tables == nil {
		return CustomAttributeValue{}, errors.New("missing custom attribute metadata")
	}
	types, err := d.constructorTypes(a.Type)
	if err != nil {
		return CustomAttributeValue{}, fmt.Errorf("custom attribute constructor: %w", err)
	}
	return decodeCustomAttributeValue(a.Value, types, d.resolveEnum)
}

func (d *CustomAttributeDecoder) constructorTypes(index CodedIndex[CustomAttributeType]) ([]CustomAttributeArgumentType, error) {
	if types, ok := d.constructors[index]; ok {
		return types, nil
	}
	var name String
	var signature []byte
	switch index.Tag {
	case CustomAttributeType_MethodDef:
		ctor, err := d.metadata.Tables.MethodDef.At(index.Index)
		if err != nil {
			return nil, err
		}
		name, signature = ctor.Name, ctor.Signature
	case CustomAttributeType_MemberRef:
		ctor, err := d.metadata.Tables.MemberRef.At(index.Index)
		if err != nil {
			return nil, err
		}
		name, signature = ctor.Name, ctor.Signature
	default:
		return nil, fmt.Errorf("invalid constructor index %v", index)
	}
	if name.String() != ".ctor" {
		return nil, fmt.Errorf("%q is not an instance constructor", name)
	}
	// Read the subset of signatures allowed for attribute constructors. Using
	// a bounded reader also rejects unsupported type shapes before allocating
	// arrays or recursively decoding arbitrary signature types.
	r := customAttributeReader{data: signature}
	if header := r.byte(); r.err != nil {
		return nil, r.err
	} else if header != sigAbbrev_HASTHIS|sigKind_DEFAULT {
		return nil, errors.New("invalid custom attribute constructor calling convention")
	}
	count := r.compressedUint32()
	if ret := d.signatureKind(&r); r.err != nil {
		return nil, r.err
	} else if ret != ElementType_VOID {
		return nil, errors.New("custom attribute constructor must return void")
	}
	if uint64(count) > uint64(len(r.data)) {
		return nil, io.ErrUnexpectedEOF
	}
	var types []CustomAttributeArgumentType
	for i := range count {
		typ := d.signatureType(&r, 0)
		if r.err != nil {
			return nil, fmt.Errorf("parameter %d: %w", i, r.err)
		}
		types = append(types, typ)
	}
	if len(r.data) != 0 {
		return nil, errors.New("trailing custom attribute constructor signature data")
	}
	d.constructors[index] = types
	return types, nil
}

func (d *CustomAttributeDecoder) signatureKind(r *customAttributeReader) ElementType {
	for {
		kind := ElementType(r.byte())
		if r.err != nil || (kind != ElementType_CMOD_OPT && kind != ElementType_CMOD_REQD) {
			return kind
		}
		d.signatureHandle(r)
	}
}

func (d *CustomAttributeDecoder) signatureHandle(r *customAttributeReader) CodedIndex[TypeDefOrRefOrSpec] {
	code := r.compressedUint32()
	if r.err != nil {
		return CodedIndex[TypeDefOrRefOrSpec]{}
	}
	index, err := parseCoded[TypeDefOrRefOrSpec](code)
	if err != nil {
		r.err = err
		return index
	}
	var count uint32
	switch index.Tag {
	case TypeDefOrRefOrSpec_TypeDef:
		count = d.metadata.Tables.TypeDef.Len()
	case TypeDefOrRefOrSpec_TypeRef:
		count = d.metadata.Tables.TypeRef.Len()
	case TypeDefOrRefOrSpec_TypeSpec:
		count = d.metadata.Tables.TypeSpec.Len()
	default:
		r.err = errors.New("invalid custom attribute signature type handle")
	}
	if r.err == nil && uint32(index.Index) >= count {
		r.err = errors.New("custom attribute signature type handle is out of range")
	}
	return index
}

func (d *CustomAttributeDecoder) signatureType(r *customAttributeReader, depth int) CustomAttributeArgumentType {
	if !r.checkDepth(depth) {
		return CustomAttributeArgumentType{}
	}
	typ := CustomAttributeArgumentType{Kind: d.signatureKind(r)}
	switch typ.Kind {
	case ElementType_BOOLEAN, ElementType_CHAR,
		ElementType_I1, ElementType_U1, ElementType_I2, ElementType_U2,
		ElementType_I4, ElementType_U4, ElementType_I8, ElementType_U8,
		ElementType_R4, ElementType_R8, ElementType_STRING:
	case ElementType_OBJECT:
		typ.Kind = ElementType_BOXED_OBJECT
	case ElementType_SZARRAY:
		element := d.signatureType(r, depth+1)
		typ.Element = &element
	case ElementType_CLASS, ElementType_VALUETYPE:
		handle := d.signatureHandle(r)
		if r.err != nil {
			break
		}
		ref, err := d.typeReference(handle, 0)
		if err != nil {
			r.err = err
			break
		}
		if typ.Kind == ElementType_CLASS {
			if ref.Namespace != "System" || ref.Name != "Type" || len(ref.DeclaringTypes) != 0 {
				r.err = fmt.Errorf("unsupported custom attribute class %q", ref.fullName())
				break
			}
			typ.Kind = ElementType_TYPE
		} else {
			typ.Kind = ElementType_ENUM
			typ.Enum = EnumReference{Metadata: ref}
			typ.EnumUnderlyingType, r.err = d.resolveEnum(typ.Enum)
		}
	default:
		if r.err == nil {
			r.err = fmt.Errorf("unsupported custom attribute signature type %v", typ.Kind)
		}
	}
	return r.normalizeType(typ, depth)
}

func (d *CustomAttributeDecoder) indexTypes() error {
	if d.typesIndexed {
		return d.typesError
	}
	d.typesIndexed = true
	d.typesError = d.buildTypeIndex()
	return d.typesError
}

func (d *CustomAttributeDecoder) indexTypeParents() error {
	if d.parentsIndexed {
		return d.parentsError
	}
	d.parentsIndexed = true
	d.parentsError = d.buildTypeParents()
	return d.parentsError
}

func (d *CustomAttributeDecoder) buildTypeParents() error {
	parents := make(map[Index]Index)
	for nested, err := range d.metadata.Tables.NestedClass.All() {
		if err != nil {
			return err
		}
		if _, ok := parents[nested.NestedClass]; ok {
			return fmt.Errorf("duplicate enclosing type for TypeDef %d", nested.NestedClass)
		}
		parents[nested.NestedClass] = nested.EnclosingClass
	}
	d.typeParents = parents
	return nil
}

func (d *CustomAttributeDecoder) buildTypeIndex() error {
	if err := d.indexTypeParents(); err != nil {
		return err
	}
	type typeIdentityInfo struct {
		identity metadataTypeIdentity
		depth    int
	}
	// Only ancestors need memoization: most types are never used as parents.
	ancestors := make(map[Index]typeIdentityInfo)
	// Share owned namespace strings while building the identity index.
	namespaces := make(map[string]string)
	// Keep the first row inline; only repeated identities need an index slice.
	d.typesByIdentity = make(map[metadataTypeIdentity]Index, d.metadata.Tables.TypeDef.Len())
	var identityOf func(Index, int) (typeIdentityInfo, error)
	identityOf = func(index Index, depth int) (typeIdentityInfo, error) {
		if depth >= maxCustomAttributeDepth {
			return typeIdentityInfo{}, errors.New("cyclic or excessively nested TypeDef")
		}
		if info, ok := ancestors[index]; ok {
			if info.depth > maxCustomAttributeDepth-depth {
				return typeIdentityInfo{}, errors.New("cyclic or excessively nested TypeDef")
			}
			return info, nil
		}
		typ, err := d.metadata.Tables.TypeDef.At(index)
		if err != nil {
			return typeIdentityInfo{}, err
		}
		namespace, ok := namespaces[typ.Namespace.String()]
		if !ok {
			namespace = typ.Namespace.String()
			namespaces[namespace] = namespace
		}
		name := typ.Name.String()
		info := typeIdentityInfo{
			identity: metadataTypeIdentity{namespace: namespace, name: name},
			depth:    1,
		}
		if parent, ok := d.typeParents[index]; ok {
			parentInfo, err := identityOf(parent, depth+1)
			if err != nil {
				return typeIdentityInfo{}, err
			}
			info.identity.namespace = parentInfo.identity.namespace
			info.identity.declaringTypes = parentInfo.identity.declaringTypes + parentInfo.identity.name + "\x00"
			info.depth = parentInfo.depth + 1
		}
		if depth != 0 {
			ancestors[index] = info
		}
		return info, nil
	}
	for index := range d.metadata.Tables.TypeDef.Indices() {
		info, err := identityOf(index, 0)
		if err != nil {
			return err
		}
		if first, ok := d.typesByIdentity[info.identity]; ok {
			if d.typeIdentityDuplicates == nil {
				d.typeIdentityDuplicates = make(map[Index][]Index)
			}
			if indices := d.typeIdentityDuplicates[first]; len(indices) != 0 {
				d.typeIdentityDuplicates[first] = append(indices, index)
			} else {
				d.typeIdentityDuplicates[first] = []Index{first, index}
			}
		} else {
			d.typesByIdentity[info.identity] = index
		}
	}
	return nil
}

func (d *CustomAttributeDecoder) indexTypeNames() error {
	if err := d.indexTypes(); err != nil {
		return err
	}
	if d.typesByName != nil {
		return nil
	}
	// Serialized names are only needed for named or boxed enum arguments.
	d.typesByName = make(map[string]Index, len(d.typesByIdentity))
	for identity, first := range d.typesByIdentity {
		ref := EnumReferenceMetadata{Namespace: identity.namespace, Name: identity.name}
		if identity.declaringTypes != "" {
			ref.DeclaringTypes = strings.Split(strings.TrimSuffix(identity.declaringTypes, "\x00"), "\x00")
		}
		name := ref.fullName()
		indices := d.typeIdentityDuplicates[first]
		if existing, ok := d.typesByName[name]; ok {
			// Distinct raw identities can have the same serialized name. Merge
			// in row order without changing either identity's index slice.
			previous := d.typeNameDuplicates[name]
			if len(previous) == 0 {
				previous = []Index{existing}
			}
			if len(indices) == 0 {
				indices = []Index{first}
			}
			indices = slices.Concat(previous, indices)
			slices.Sort(indices)
			first = indices[0]
		}
		d.typesByName[name] = first
		if len(indices) != 0 {
			if d.typeNameDuplicates == nil {
				d.typeNameDuplicates = make(map[string][]Index)
			}
			d.typeNameDuplicates[name] = indices
		}
	}
	return nil
}

func (d *CustomAttributeDecoder) typeReference(index CodedIndex[TypeDefOrRefOrSpec], depth int) (*EnumReferenceMetadata, error) {
	if depth >= maxCustomAttributeDepth {
		return nil, errors.New("cyclic or excessively nested type reference")
	}
	if ref, ok := d.typeReferences[index]; ok {
		if len(ref.DeclaringTypes) >= maxCustomAttributeDepth-depth {
			return nil, errors.New("cyclic or excessively nested type reference")
		}
		return ref, nil
	}
	ref := &EnumReferenceMetadata{Handle: index}
	var parent *EnumReferenceMetadata
	switch index.Tag {
	case TypeDefOrRefOrSpec_TypeDef:
		if err := d.indexTypeParents(); err != nil {
			return nil, err
		}
		def, err := d.metadata.Tables.TypeDef.At(index.Index)
		if err != nil {
			return nil, err
		}
		ref.Namespace, ref.Name = def.Namespace.String(), def.Name.String()
		if enclosing, ok := d.typeParents[index.Index]; ok {
			parent, err = d.typeReference(CodedIndex[TypeDefOrRefOrSpec]{Tag: TypeDefOrRefOrSpec_TypeDef, Index: enclosing}, depth+1)
			if err != nil {
				return nil, err
			}
		}
	case TypeDefOrRefOrSpec_TypeRef:
		typ, err := d.metadata.Tables.TypeRef.At(index.Index)
		if err != nil {
			return nil, err
		}
		ref.Namespace, ref.Name = typ.Namespace.String(), typ.Name.String()
		switch typ.ResolutionScope.Tag {
		case ResolutionScope_TypeRef:
			parent, err = d.typeReference(CodedIndex[TypeDefOrRefOrSpec]{Tag: TypeDefOrRefOrSpec_TypeRef, Index: typ.ResolutionScope.Index}, depth+1)
		case ResolutionScope_Module:
			_, err = d.metadata.Tables.Module.At(typ.ResolutionScope.Index)
		case ResolutionScope_AssemblyRef:
			var assembly AssemblyRef
			assembly, err = d.metadata.Tables.AssemblyRef.At(typ.ResolutionScope.Index)
			ref.Assembly = &assembly
		default:
			return nil, fmt.Errorf("unsupported resolution scope for custom attribute type %q", ref.Name)
		}
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported custom attribute TypeSpec or null type")
	}
	if parent != nil {
		ref.Namespace = parent.Namespace
		ref.Assembly = parent.Assembly
		ref.DeclaringTypes = make([]string, len(parent.DeclaringTypes)+1)
		copy(ref.DeclaringTypes, parent.DeclaringTypes)
		ref.DeclaringTypes[len(parent.DeclaringTypes)] = parent.Name
	}
	d.typeReferences[index] = ref
	return ref, nil
}

func (d *CustomAttributeDecoder) resolveEnum(ref EnumReference) (ElementType, error) {
	var underlying ElementType
	var err error
	if typ := ref.Metadata; typ != nil {
		if cached, ok := d.enumsByType[typ.Handle]; ok {
			return cached, nil
		}
		switch typ.Handle.Tag {
		case TypeDefOrRefOrSpec_TypeDef:
			underlying, err = d.metadata.EnumUnderlyingType(typ.Handle.Index)
		case TypeDefOrRefOrSpec_TypeRef:
			if typ.Assembly == nil {
				underlying, err = d.resolveLocalMetadataEnum(typ)
			}
		default:
			return 0, errors.New("invalid custom attribute enum metadata reference")
		}
	} else {
		if cached, ok := d.enumsByName[ref.SerializedName]; ok {
			return cached, nil
		}
		localName, assemblyName, qualified := splitTypeName(ref.SerializedName)
		local := !qualified
		if qualified && !strings.Contains(assemblyName, ",") && d.metadata.Tables.Assembly.Len() == 1 {
			assembly, err := d.metadata.Tables.Assembly.At(0)
			if err != nil {
				return 0, err
			}
			local = strings.EqualFold(strings.TrimSpace(assemblyName), assembly.Name.String())
		}
		if local {
			underlying, err = d.resolveLocalEnum(localName)
		}
	}
	if err != nil {
		return 0, err
	}
	if underlying == 0 {
		if d.ResolveEnum == nil {
			return 0, &UnresolvedEnumError{Reference: ref}
		}
		underlying, err = d.ResolveEnum(ref)
		if err != nil {
			return 0, err
		}
	}
	if !isCustomAttributeEnumType(underlying) {
		return 0, fmt.Errorf("unsupported underlying type %v for enum %q", underlying, ref.name())
	}
	if ref.Metadata != nil {
		d.enumsByType[ref.Metadata.Handle] = underlying
	} else {
		d.enumsByName[ref.SerializedName] = underlying
	}
	return underlying, nil
}

func (d *CustomAttributeDecoder) resolveLocalEnum(name string) (ElementType, error) {
	if err := d.indexTypeNames(); err != nil {
		return 0, err
	}
	first, ok := d.typesByName[name]
	if !ok {
		return 0, nil
	}
	if indices := d.typeNameDuplicates[name]; len(indices) != 0 {
		return d.enumTypeFromDefinitions(indices, name)
	}
	return d.metadata.EnumUnderlyingType(first)
}

func (d *CustomAttributeDecoder) resolveLocalMetadataEnum(ref *EnumReferenceMetadata) (ElementType, error) {
	if err := d.indexTypes(); err != nil {
		return 0, err
	}
	first, ok := d.typesByIdentity[ref.identity()]
	if !ok {
		return 0, nil
	}
	if indices := d.typeIdentityDuplicates[first]; len(indices) != 0 {
		return d.enumTypeFromDefinitions(indices, ref.fullName())
	}
	return d.metadata.EnumUnderlyingType(first)
}

func (d *CustomAttributeDecoder) enumTypeFromDefinitions(indices []Index, name string) (ElementType, error) {
	var underlying ElementType
	for _, index := range indices {
		typ, err := d.metadata.EnumUnderlyingType(index)
		if err != nil {
			return 0, err
		}
		if underlying != 0 && underlying != typ {
			return 0, fmt.Errorf("ambiguous underlying type for enum %q", name)
		}
		underlying = typ
	}
	return underlying, nil
}

// typeNameEscaper converts literal metadata identifiers into serialized type-name
// components for lookup. Escaping distinguishes literal '+' and ',' characters
// from nesting and assembly separators. The other escapes preserve literal
// identifiers too; they do not imply support for pointer, array, or generic types.
// Names read from attribute blobs are left unchanged.
// See https://learn.microsoft.com/dotnet/fundamentals/reflection/specifying-fully-qualified-type-names#specify-special-characters.
var typeNameEscaper = strings.NewReplacer(
	`\`, `\\`,
	`+`, `\+`,
	`,`, `\,`,
	`&`, `\&`,
	`*`, `\*`,
	`[`, `\[`,
	`]`, `\]`,
)

// splitTypeName separates an optional assembly qualifier at the first unescaped
// comma. Type-name whitespace is significant and is preserved.
func splitTypeName(name string) (typeName, assembly string, qualified bool) {
	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '\\':
			i++
		case ',':
			return name[:i], name[i+1:], true
		}
	}
	return name, "", false
}
