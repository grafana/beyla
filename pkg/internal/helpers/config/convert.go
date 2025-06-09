package config

import (
	"fmt"
	"reflect"
)

const SkipConversion = "(skip)"

func Convert(
	src, dst any,
	fieldHints map[string]string,
) error {
	if fieldHints == nil {
		fieldHints = map[string]string{}
	}
	return convert(".", reflect.ValueOf(src), reflect.ValueOf(dst), fieldHints)
}

func convert(
	prefix string,
	src, dst reflect.Value,
	fieldHints map[string]string,
) error {
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
			return fmt.Errorf("source is nil pointer")
		}
		srcValue = src.Elem()
	}

	if srcValue.Kind() == reflect.Struct && dstElem.Kind() == reflect.Struct {
		return convertStruct(prefix, srcValue, dstElem, fieldHints)
	}

	if srcValue.Type().AssignableTo(dstElem.Type()) {
		dstElem.Set(srcValue)
		return nil
	}
	if srcValue.Type().ConvertibleTo(dstElem.Type()) {
		dstElem.Set(srcValue.Convert(dstElem.Type()))
		return nil
	}

	return fmt.Errorf("field %s: cannot convert %s to %s", prefix, srcValue.Type(), dstElem.Type())
}

func handleFieldConversion(
	prefix string,
	srcField, dstField reflect.Value,
	fieldHints map[string]string,
) error {
	// Direct assignment if types match
	if srcField.Type().AssignableTo(dstField.Type()) {
		dstField.Set(srcField)
		return nil
	}

	// Type conversion if possible
	if srcField.Type().ConvertibleTo(dstField.Type()) {
		dstField.Set(srcField.Convert(dstField.Type()))
		return nil
	}

	// For struct fields, we need recursive handling
	if srcField.Kind() == reflect.Struct && dstField.Kind() == reflect.Struct {
		return convertStruct(prefix, srcField, dstField, fieldHints)
	}

	// For pointer fields, create new instance if needed
	if srcField.Kind() == reflect.Ptr && dstField.Kind() == reflect.Ptr {
		if srcField.IsNil() {
			// Source is nil, nothing to convert
			return nil
		}

		if dstField.IsNil() {
			// Create a new instance of the destination type
			dstField.Set(reflect.New(dstField.Type().Elem()))
		}

		// Convert what the pointers point to
		return convert(prefix, srcField.Elem(), dstField, fieldHints)
	}

	return fmt.Errorf("field %s: cannot convert %s to %s", prefix, srcField.Type(), dstField.Type())
}

func convertStruct(
	prefix string,
	src, dst reflect.Value,
	fieldHints map[string]string,
) error {
	srcVals := structFieldValues(src)
	dstVals := structFieldValues(dst)

	for dn, dv := range dstVals {
		srcName := dn
		if hint, ok := fieldHints[prefix+dn]; ok {
			srcName = hint
		}
		if sv, ok := srcVals[srcName]; ok {
			if err := handleFieldConversion(prefix+dn+".", sv, dv, fieldHints); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("dst field %s: cannot find field %s in source",
				prefix+dn, srcName)
		}
	}
	return nil
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
