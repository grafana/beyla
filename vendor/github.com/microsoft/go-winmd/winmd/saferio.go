// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import "io"

// Copied from "internal/saferio".
// https://github.com/golang/go/blob/bd56cb90a72e6725eddb9622e93a0806c1d1f105/src/internal/saferio/io.go

const chunk = 10 << 20 // 10M

// readData reads n bytes from the input stream, but avoids allocating
// all n bytes if n is large. This avoids crashing the program by
// allocating all n bytes in cases where n is incorrect.
//
// The error is io.EOF only if no bytes were read.
// If an io.EOF happens after reading some but not all the bytes,
// ReadData returns io.ErrUnexpectedEOF.
func readData(r io.Reader, n uint64) ([]byte, error) {
	if int64(n) < 0 || n != uint64(int(n)) {
		// n is too large to fit in int, so we can't allocate
		// a buffer large enough. Treat this as a read failure.
		return nil, io.ErrUnexpectedEOF
	}

	if n < chunk {
		buf := make([]byte, n)
		_, err := io.ReadFull(r, buf)
		if err != nil {
			return nil, err
		}
		return buf, nil
	}

	var buf []byte
	buf1 := make([]byte, chunk)
	for n > 0 {
		next := n
		if next > chunk {
			next = chunk
		}
		_, err := io.ReadFull(r, buf1[:next])
		if err != nil {
			if len(buf) > 0 && err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		buf = append(buf, buf1[:next]...)
		n -= next
	}
	return buf, nil
}
