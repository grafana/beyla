// Copyright (c) 2021, Peter Ohler, All rights reserved.

package alt

import (
	"reflect"
	"strconv"
	"unsafe"
)

var uintValFuncs = [8]valFunc{
	valUint,
	valUintAsString,
	valUintNotEmpty,
	valUintNotEmptyAsString,
	ivalUint,
	ivalUintAsString,
	ivalUintNotEmpty,
	ivalUintNotEmptyAsString,
}

func valUint(fi *finfo, rv reflect.Value, addr uintptr) (any, reflect.Value, bool) {
	return *(*uint)(unsafe.Pointer(addr + fi.offset)), nilValue, false
}

func valUintAsString(fi *finfo, rv reflect.Value, addr uintptr) (any, reflect.Value, bool) {
	return strconv.FormatUint(uint64(*(*uint)(unsafe.Pointer(addr + fi.offset))), 10), nilValue, false
}

func valUintNotEmpty(fi *finfo, rv reflect.Value, addr uintptr) (any, reflect.Value, bool) {
	v := *(*uint)(unsafe.Pointer(addr + fi.offset))
	return v, nilValue, v == 0
}

func valUintNotEmptyAsString(fi *finfo, rv reflect.Value, addr uintptr) (any, reflect.Value, bool) {
	v := *(*uint)(unsafe.Pointer(addr + fi.offset))
	if v == 0 {
		return nil, nilValue, true
	}
	return strconv.FormatUint(uint64(v), 10), nilValue, false
}

func ivalUint(fi *finfo, rv reflect.Value, addr uintptr) (any, reflect.Value, bool) {
	return rv.FieldByIndex(fi.index).Uint(), nilValue, false
}

func ivalUintAsString(fi *finfo, rv reflect.Value, addr uintptr) (any, reflect.Value, bool) {
	return strconv.FormatUint(rv.FieldByIndex(fi.index).Uint(), 10), nilValue, false
}

func ivalUintNotEmpty(fi *finfo, rv reflect.Value, addr uintptr) (any, reflect.Value, bool) {
	v := rv.FieldByIndex(fi.index).Uint()
	return v, nilValue, v == 0
}

func ivalUintNotEmptyAsString(fi *finfo, rv reflect.Value, addr uintptr) (any, reflect.Value, bool) {
	v := rv.FieldByIndex(fi.index).Uint()
	if v == 0 {
		return nil, nilValue, true
	}
	return strconv.FormatUint(v, 10), nilValue, false
}
