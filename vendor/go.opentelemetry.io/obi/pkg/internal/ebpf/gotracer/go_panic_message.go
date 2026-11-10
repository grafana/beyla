// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"fmt"
	"go/version"
	"math"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

func goPanicMessage(pid app.PID, p *BpfGoExceptionPayloadT) string {
	rawMessage := unix.ByteSliceToString(p.Message[:])
	message := attributes.SanitizeUTF8(rawMessage)
	typ, ok := goExceptionValueType(pid, p.ValueType)
	stringValue := typ.Kind == uint8(reflect.String) && !typ.Methods
	runtimeError := typ.ErrorFunc == "runtime.errorString.Error" ||
		typ.ErrorFunc == "runtime.errorAddressString.Error"
	plainError := typ.ErrorFunc == "runtime.plainError.Error"
	// These standard-library pointer types store their Error() text first.
	standardError := typ.Kind == uint8(reflect.Pointer) &&
		(typ.ErrorFunc == "errors.(*errorString).Error" ||
			typ.ErrorFunc == "fmt.(*wrapError).Error" || typ.ErrorFunc == "fmt.(*wrapErrors).Error")
	// BPF reads can fail when constant message bytes are on a nonresident page.
	// Recover them from the executable using the captured string address and length.
	if ok && (stringValue || runtimeError || plainError || standardError) && rawMessage == "" &&
		p.ValueRead&goValueHeaderRead != 0 && p.Value[1] > 0 {
		size := min(p.Value[1], uint64(len(p.Message)-1))
		if data, read := goExceptionReadOnlyData(pid, p.Value[0], size); read {
			message = attributes.SanitizeUTF8(unix.ByteSliceToString(data))
		}
	}
	switch {
	case !ok:
		if p.ValueRead&goValueStringType == 0 {
			message = ""
		}
	case typ.Predeclared && !typ.Methods && p.ValueRead&goValueScalarRead != 0:
		message = goScalarPanicMessage(p.Value[0], reflect.Kind(typ.Kind))
	case typ.ErrorFunc == "runtime.boundsError.Error":
		message = ""
		// On supported little-endian targets, signed and code occupy the
		// first two bytes of boundsError's third word.
		signed, code := uint8(p.Value[2]), uint8(p.Value[2]>>8)
		if p.ValueRead&(goValueHeaderRead|goValueTailRead) == goValueHeaderRead|goValueTailRead && signed <= 1 {
			message = goBoundsErrorMessage(p.Value[0], p.Value[1], signed != 0, code, typ.GoVersion)
		}
	case runtimeError:
		if message != "" {
			message = "runtime error: " + message
		}
	case stringValue || plainError || standardError:
		// These types return the captured string directly.
	default:
		message = ""
	}
	return message
}

func goScalarPanicMessage(value uint64, kind reflect.Kind) string {
	switch kind {
	case reflect.Bool:
		if value <= 1 {
			return strconv.FormatBool(value != 0)
		}
	case reflect.Int, reflect.Int64:
		return strconv.FormatInt(int64(value), 10)
	case reflect.Int8:
		return strconv.FormatInt(int64(int8(value)), 10)
	case reflect.Int16:
		return strconv.FormatInt(int64(int16(value)), 10)
	case reflect.Int32:
		return strconv.FormatInt(int64(int32(value)), 10)
	case reflect.Uint, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(value, 10)
	case reflect.Uint8:
		return strconv.FormatUint(uint64(uint8(value)), 10)
	case reflect.Uint16:
		return strconv.FormatUint(uint64(uint16(value)), 10)
	case reflect.Uint32:
		return strconv.FormatUint(uint64(uint32(value)), 10)
	}
	return ""
}

// Mirrors Go's codes in the runtime boundsError value.
const (
	goBoundsIndex      = 0
	goBoundsSliceAlen  = 1
	goBoundsSliceAcap  = 2
	goBoundsSliceB     = 3
	goBoundsSlice3Alen = 4
	goBoundsSlice3Acap = 5
	goBoundsSlice3B    = 6
	goBoundsSlice3C    = 7
	goBoundsConvert    = 8
)

func goBoundsErrorMessage(x, y uint64, signed bool, code uint8, goVersion string) string {
	if y > math.MaxInt64 {
		return ""
	}
	if code == goBoundsConvert {
		goVersion, _, _ = strings.Cut(goVersion, " ")
		if !version.IsValid(goVersion) || x > math.MaxInt64 {
			return ""
		}
		target := "pointer to array"
		if version.Compare(goVersion, "go1.20") >= 0 {
			target = "array or pointer to array"
		}
		return fmt.Sprintf("runtime error: cannot convert slice with length %d to %s with length %d", y, target, x)
	}
	if code == goBoundsSliceAlen || code == goBoundsSliceAcap || code == goBoundsSlice3Alen || code == goBoundsSlice3Acap {
		prefix := ":"
		if code == goBoundsSlice3Alen || code == goBoundsSlice3Acap {
			prefix = "::"
		}
		if signed && int64(x) < 0 {
			return fmt.Sprintf("runtime error: slice bounds out of range [%s%d]", prefix, int64(x))
		}
		limit := "length"
		if code == goBoundsSliceAcap || code == goBoundsSlice3Acap {
			limit = "capacity"
		}
		return fmt.Sprintf("runtime error: slice bounds out of range [%s%d] with %s %d", prefix, x, limit, y)
	}
	if code == goBoundsSliceB || code == goBoundsSlice3B || code == goBoundsSlice3C {
		prefix, suffix := "", ""
		if code == goBoundsSlice3B {
			prefix = ":"
		}
		if code == goBoundsSlice3C {
			suffix = ":"
		}
		if signed && int64(x) < 0 {
			return fmt.Sprintf("runtime error: slice bounds out of range [%s%d:%s]", prefix, int64(x), suffix)
		}
		return fmt.Sprintf("runtime error: slice bounds out of range [%s%d:%d%s]", prefix, x, y, suffix)
	}
	if code != goBoundsIndex {
		return ""
	}
	if signed && int64(x) < 0 {
		return fmt.Sprintf("runtime error: index out of range [%d]", int64(x))
	}
	index := strconv.FormatUint(x, 10)
	return fmt.Sprintf("runtime error: index out of range [%s] with length %d", index, y)
}
