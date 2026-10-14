// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"strconv"
	"strings"
)

// flagName matches a complete masked field, or an individual bit when mask and
// value are equal. The generated, checked-in tables define names and output
// order; they are never modified at runtime.
type flagName[T ~int8 | ~uint8 | ~uint16 | ~uint32] struct {
	mask  T
	value T
	name  string
}

func formatEnum[T ~int8 | ~uint8 | ~uint16 | ~uint32](value T, names []flagName[T], typeName string) string {
	for _, entry := range names {
		if value == entry.value {
			return entry.name
		}
	}
	// All supported integer types fit in int64, including uint32.
	return typeName + "(" + strconv.FormatInt(int64(value), 10) + ")"
}

func formatFlags[T ~uint8 | ~uint16 | ~uint32](value T, names []flagName[T]) string {
	var text strings.Builder
	remaining := value
	for _, entry := range names {
		// Match against the original value, not the remainder: clearing a
		// nonzero choice must not also select that field's zero-valued default.
		if value&entry.mask != entry.value {
			continue
		}
		if text.Len() != 0 {
			text.WriteByte('|')
		}
		text.WriteString(entry.name)
		remaining &^= entry.mask
	}
	if remaining != 0 {
		if text.Len() != 0 {
			text.WriteByte('|')
		}
		text.WriteString("0x")
		text.WriteString(strconv.FormatUint(uint64(remaining), 16))
	}
	if text.Len() == 0 {
		return "0"
	}
	return text.String()
}
