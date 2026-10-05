// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"unicode/utf16"
	"unicode/utf8"
)

// DecodeCompressedUint32 decodes an unsigned integer from the start of data,
// as defined in ECMA-335 §II.23.2. The encoding uses 1, 2, or 4 bytes and supports
// values up to 0x1fffffff.
//
// It returns the decoded value and the number of bytes consumed. On error,
// both are zero. Empty or truncated input returns [io.ErrUnexpectedEOF].
func DecodeCompressedUint32(data []byte) (result uint32, n int, err error) {
	if len(data) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	// The first byte determines the amount of data to read.
	const (
		mask1 byte = 0b_1000_0000
		mask2 byte = 0b_1100_0000
		mask3 byte = 0b_1110_0000
	)
	v := data[0]
	if v&mask1 == 0 {
		return uint32(v & ^mask1), 1, nil
	}
	if v&mask2 == mask1 {
		if len(data) < 2 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		// If the first two bytes are 10bb_bbbb and x, then the rest of the blob
		// contains the (00bb_bbbb << 8 + x) bytes of actual data.
		return uint32(v & ^mask2)<<8 + uint32(data[1]), 2, nil
	}
	if v&mask3 == mask2 {
		if len(data) < 4 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		// If the first four bytes are 110b_bbbb, x, y, and z, then the rest of the
		// blob contains the (000b_bbbb << 24 + x << 16 + y << 8 + z) bytes of actual data.
		return uint32(v & ^mask3)<<24 + uint32(data[1])<<16 + uint32(data[2])<<8 + uint32(data[3]), 4, nil
	}
	// All first three bits are 1. Not a valid compressed uint32.
	return 0, 0, fmt.Errorf("unable to decompress uint32 due to invalid length: %d", v)
}

// DecodeCompressedInt32 decodes a signed integer from the start of data,
// as defined in ECMA-335 §II.23.2. The encoding uses 1, 2, or 4 bytes and supports
// values from -268435456 to 268435455.
//
// It returns the decoded value and the number of bytes consumed. On error,
// both are zero. Empty or truncated input returns [io.ErrUnexpectedEOF].
func DecodeCompressedInt32(data []byte) (result int32, n int, err error) {
	// Based on .NET System.Reflection.Metadata.BlobReader TryReadCompressedSignedInteger.
	// https://github.com/dotnet/runtime/blob/582e522d6e164de6f9c961bc3cce226a241b11e5/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/BlobReader.cs#L490
	u, n, err := DecodeCompressedUint32(data)
	if err != nil {
		return 0, 0, err
	}
	result = int32(u >> 1)
	// If sign extend bit is 1.
	if u&0x1 != 0 {
		switch n {
		case 1:
			result |= ^int32(^uint32(0xffff_ffc0))
		case 2:
			result |= ^int32(^uint32(0xffff_e000))
		case 4:
			result |= ^int32(^uint32(0xf000_0000))
		default:
			return 0, 0, fmt.Errorf("unable to decompress int32 due to invalid length %d", n)
		}
	}
	return result, n, nil
}

// DecodeSerString decodes a serialized string (SerString) from the start of data,
// as defined in ECMA-335 §II.23.3. A SerString is a compressed byte count followed
// by UTF-8 bytes, or a single 0xff byte representing null.
//
// It returns the UTF-8 bytes and the total number of bytes consumed, including
// the length prefix or null marker. The result aliases data and its capacity
// equals its length. A null string returns nil; an empty string returns a
// non-nil, zero-length slice. The input is not modified. Copy the result before
// modifying it if the input belongs to read-only metadata.
//
// On error, the result is nil and the byte count is zero. Empty or truncated
// input returns [io.ErrUnexpectedEOF]. Invalid prefixes or UTF-8 return an error.
func DecodeSerString(data []byte) (result []byte, n int, err error) {
	if len(data) > 0 && data[0] == 0xff {
		return nil, 1, nil
	}
	length, prefix, err := DecodeCompressedUint32(data)
	if err != nil {
		return nil, 0, err
	}
	if int(length) > len(data)-prefix {
		return nil, 0, io.ErrUnexpectedEOF
	}
	end := prefix + int(length)
	result = data[prefix:end:end]
	if !utf8.Valid(result) {
		return nil, 0, errors.New("invalid UTF-8 in serialized string")
	}
	return result, end, nil
}

// DecodeConstant decodes a Constant.Value blob of type typ, as defined in
// ECMA-335 §II.22.9. Data must contain the entire value, without a length prefix.
//
// The result is bool for ElementType_BOOLEAN, uint16 for ElementType_CHAR,
// the matching fixed-width Go integer type for ElementType_I1 through
// ElementType_U8, float32 or float64 for ElementType_R4 or ElementType_R8,
// string for ElementType_STRING, and nil for ElementType_CLASS.
// The input is not modified, and the result does not alias it.
//
// Numeric values are little-endian. A nonzero Boolean byte represents true.
// Strings are UTF-16LE without a terminator; unpaired surrogates are replaced
// with U+FFFD, as in [utf16.Decode]. Null references must be four zero bytes.
//
// On error, the result is nil. Truncated values, including odd-length strings,
// return [io.ErrUnexpectedEOF]. Invalid types, extra fixed-width value bytes,
// and nonzero null references return an error.
func DecodeConstant(typ ElementType, data []byte) (any, error) {
	if typ == ElementType_STRING {
		if len(data)%2 != 0 {
			return nil, io.ErrUnexpectedEOF
		}
		chars := make([]uint16, len(data)/2)
		for i := range chars {
			chars[i] = binary.LittleEndian.Uint16(data[i*2:])
		}
		return string(utf16.Decode(chars)), nil
	}

	var size int
	switch typ {
	case ElementType_BOOLEAN, ElementType_I1, ElementType_U1:
		size = 1
	case ElementType_CHAR, ElementType_I2, ElementType_U2:
		size = 2
	case ElementType_I4, ElementType_U4, ElementType_R4, ElementType_CLASS:
		size = 4
	case ElementType_I8, ElementType_U8, ElementType_R8:
		size = 8
	default:
		return nil, fmt.Errorf("unsupported constant type %v", typ)
	}
	if len(data) < size {
		return nil, io.ErrUnexpectedEOF
	}
	if len(data) > size {
		return nil, fmt.Errorf("invalid %v constant length: got %d bytes, want %d", typ, len(data), size)
	}

	switch typ {
	case ElementType_BOOLEAN:
		return data[0] != 0, nil
	case ElementType_CHAR, ElementType_U2:
		return binary.LittleEndian.Uint16(data), nil
	case ElementType_I1:
		return int8(data[0]), nil
	case ElementType_U1:
		return data[0], nil
	case ElementType_I2:
		return int16(binary.LittleEndian.Uint16(data)), nil
	case ElementType_I4:
		return int32(binary.LittleEndian.Uint32(data)), nil
	case ElementType_U4:
		return binary.LittleEndian.Uint32(data), nil
	case ElementType_I8:
		return int64(binary.LittleEndian.Uint64(data)), nil
	case ElementType_U8:
		return binary.LittleEndian.Uint64(data), nil
	case ElementType_R4:
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), nil
	case ElementType_R8:
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), nil
	case ElementType_CLASS:
		if binary.LittleEndian.Uint32(data) != 0 {
			return nil, errors.New("nonzero null reference constant")
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported constant type %v", typ)
	}
}

// DecodeValue decodes c.Value according to c.Type using [DecodeConstant].
func (c Constant) DecodeValue() (any, error) {
	return DecodeConstant(c.Type, c.Value)
}
