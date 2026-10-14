// Copyright (c) 2026, Peter Ohler, All rights reserved.

package alt

import (
	"hash/crc64"
	"math"
	"sort"
	"time"
)

var emcaTable = crc64.MakeTable(crc64.ECMA)

// Checksum of the provided data using a custom encoding and checksum
// routine. The functions is most efficient with simple data.
func Checksum(v any) uint64 {
	return crc64.Checksum(checksumAppend(nil, v), emcaTable)
}

func checksumAppend(b []byte, v any) []byte {
	switch tv := v.(type) {
	case nil:
		b = append(b, 0)
	case bool:
		if tv {
			b = append(b, "true"...)
		} else {
			b = append(b, "false"...)
		}
	case int:
		b = appendUint64(b, uint64(tv))
	case int8:
		b = appendUint64(b, uint64(tv))
	case int16:
		b = appendUint64(b, uint64(tv))
	case int32:
		b = appendUint64(b, uint64(tv))
	case int64:
		b = appendUint64(b, uint64(tv))
	case uint:
		b = appendUint64(b, uint64(tv))
	case uint8:
		b = appendUint64(b, uint64(tv))
	case uint16:
		b = appendUint64(b, uint64(tv))
	case uint32:
		b = appendUint64(b, uint64(tv))
	case uint64:
		b = appendUint64(b, tv)
	case float32:
		b = appendUint64(b, math.Float64bits(float64(tv)))
	case float64:
		b = appendUint64(b, math.Float64bits(tv))
	case string:
		b = append(b, tv...)
	case []byte:
		b = append(b, tv...)
	case time.Time:
		b = appendUint64(b, uint64(tv.UnixNano()))
		_, zone := tv.Zone()
		b = appendUint64(b, uint64(zone))
	case []any:
		b = append(b, '[')
		for _, v2 := range tv {
			b = checksumAppend(b, v2)
			b = append(b, ',')
		}
		b = append(b, ']')
	case map[string]any:
		keys := make([]string, 0, len(tv))
		for k := range tv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b = append(b, '{')
		for _, k := range keys {
			b = append(b, k...)
			b = append(b, ':')
			b = checksumAppend(b, tv[k])
			b = append(b, ',')
		}
		b = append(b, '}')
	case Simplifier:
		b = checksumAppend(b, tv.Simplify())
	default:
		b = checksumAppend(b, Decompose(tv))
	}
	return b
}

func appendUint64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56),
		byte(v>>48),
		byte(v>>40),
		byte(v>>32),
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}
