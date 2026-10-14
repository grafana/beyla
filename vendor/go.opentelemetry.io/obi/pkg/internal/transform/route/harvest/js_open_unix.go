// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openJSFileForScan(path string) (*os.File, bool, error) {
	// Open nonblocking so a path swapped to a FIFO or device cannot block
	// before Fstat validates the opened file.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, false, nil
		}
		return nil, false, skipChangedNonRegularFile(path, err)
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size > MaxJSFileScanBytes {
		unix.Close(fd)
		return nil, false, nil
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, false, errors.New("create file from scan fd")
	}

	return file, true, nil
}

func skipChangedNonRegularFile(path string, openErr error) error {
	info, statErr := os.Lstat(path)
	if statErr == nil && (!info.Mode().IsRegular() || info.Size() > MaxJSFileScanBytes) {
		return nil
	}
	return openErr
}
