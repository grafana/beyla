package config

import (
	"fmt"
	"reflect"
)

const SkipConversion = "(skip)"

// Convert converts a struct from src to dst, when they have different types but similar structures
// and names.
//
// The conversion is done recursively, so that nested structs are also converted.
//
// The conversion is done by matching the field names of the source and destination structs.
// If the field names do not match, the field name can be specified in the fieldHints map.
//
// The fieldHints map is used to specify the field name of the source struct for a field
func Convert(
	src, dst any,
	fieldHints map[string]string,
) {
	if fieldHints == nil {
		fieldHints = map[string]string{}
	}
	convert(".", reflect.ValueOf(src), reflect.ValueOf(dst), fieldHints)
}

func convert(
	prefix string,
	src, dst reflect.Value,
	fieldHints map[string]string,
) {
	// Handle pointers - make sure dst is a non-nil pointer
	if dst.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("%s: destination must be a pointer, got %v", prefix, dst.Kind()))
	}
	if dst.IsNil() {
		panic(prefix + ": destination is nil pointer")
	}

	dstElem := dst.Elem()

	// Handle src pointer if needed
	srcValue := src
	if src.Kind() == reflect.Ptr {
		if src.IsNil() {
			panic(prefix + ": source is nil pointer")
		}
		srcValue = src.Elem()
	}

	handleFieldConversion(prefix, srcValue, dstElem, fieldHints)
}

func handleFieldConversion(
	prefix string,
	srcField, dstField reflect.Value,
	fieldHints map[string]string,
) {
	// Direct assignment if types match
	if srcField.Type().AssignableTo(dstField.Type()) {
		dstField.Set(srcField)
		return
	}

	// Type conversion if possible
	if srcField.Type().ConvertibleTo(dstField.Type()) {
		dstField.Set(srcField.Convert(dstField.Type()))
		return
	}

	// For struct fields, we need recursive handling
	if srcField.Kind() == reflect.Struct && dstField.Kind() == reflect.Struct {
		convertStruct(prefix, srcField, dstField, fieldHints)
		return
	}

	// For pointer fields, create new instance if needed
	if srcField.Kind() == reflect.Ptr && dstField.Kind() == reflect.Ptr {
		if srcField.IsNil() {
			// Source is nil, nothing to convert
			return
		}

		if dstField.IsNil() {
			// Create a new instance of the destination type
			dstField.Set(reflect.New(dstField.Type().Elem()))
		}

		// Convert what the pointers point to
		convert(prefix, srcField.Elem(), dstField, fieldHints)
		return
	}

	panic(fmt.Sprintf("field %s: cannot convert %s to %s", prefix, srcField.Type(), dstField.Type()))
}

func convertStruct(
	prefix string,
	src, dst reflect.Value,
	fieldHints map[string]string,
) {
	srcVals := structFieldValues(src)
	dstVals := structFieldValues(dst)

	for dn, dv := range dstVals {
		srcName := dn
		if hint, ok := fieldHints[prefix+dn]; ok {
			srcName = hint
		}
		if sv, ok := srcVals[srcName]; ok {
			handleFieldConversion(prefix+dn+".", sv, dv, fieldHints)
		} else if srcName != SkipConversion {
			panic(fmt.Sprintf("dst field %s: cannot find field %s in source",
				prefix+dn, srcName))
		}
	}
}

func structFieldValues(str reflect.Value) map[string]reflect.Value {
	m := make(map[string]reflect.Value, str.NumField())
	for i := 0; i < str.NumField(); i++ {
		// ignoring private fields
		if f := str.Type().Field(i); f.IsExported() {
			m[f.Name] = str.Field(i)
		}
	}
	return m
}
