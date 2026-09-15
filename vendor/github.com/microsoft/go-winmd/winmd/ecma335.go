// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import "fmt"

// DecodeCompressedUint32 converts 1-4 compressed bytes into one uint32, as defined in §II.23.2.
// Returns the result and the number of bytes read to obtain the result, or an error.
func decodeCompressedUint32(data []byte) (result uint32, n int, err error) {
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
		// If the first two bytes are 10bb_bbbb and x, then the rest of the blob
		// contains the (00bb_bbbb << 8 + x) bytes of actual data.
		return uint32(v & ^mask2)<<8 + uint32(data[1]), 2, nil
	}
	if v&mask3 == mask2 {
		// If the first four bytes are 110b_bbbb, x, y, and z, then the rest of the
		// blob contains the (000b_bbbb << 24 + x << 16 + y << 8 + z) bytes of actual data.
		return uint32(v & ^mask3)<<24 + uint32(data[1])<<16 + uint32(data[2])<<8 + uint32(data[3]), 4, nil
	}
	// All first three bits are 1. Not a valid compressed uint32.
	return 0, 0, fmt.Errorf("unable to decompress uint32 due to invalid length: %d", v)
}

// DecodeCompressedInt32 converts 1-4 compressed bytes into one int32, as defined in §II.23.2.
// Returns the result and the number of bytes read to obtain the result, or an error.
func decodeCompressedInt32(data []byte) (result int32, n int, err error) {
	// Based on .NET System.Reflection.Metadata.BlobReader TryReadCompressedSignedInteger.
	// https://github.com/dotnet/runtime/blob/582e522d6e164de6f9c961bc3cce226a241b11e5/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/BlobReader.cs#L490
	u, n, err := decodeCompressedUint32(data)
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
