// Adapted code from
// https://cs.opensource.google/go/x/exp/+/43b7b7cd:mmap/mmap_unix.go
// which allows for direct data access (no copies)

package addrinfo

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
)

type mmap struct {
	data []byte
}

func (m *mmap) Close() error {

	if len(m.data) == 0 {
		m.data = nil
		return nil
	}

	data := m.data

	m.data = nil

	runtime.SetFinalizer(m, nil)

	return syscall.Munmap(data)
}

func mapFile(filename string) (*mmap, error) {
	f, err := os.Open(filename)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	fi, err := f.Stat()

	if err != nil {
		return nil, err
	}

	size := fi.Size()

	if size == 0 {
		return &mmap{
			data: make([]byte, 0),
		}, nil
	}

	if size < 0 {
		return nil, fmt.Errorf("mmap: file %q has negative size", filename)
	}

	if size != int64(int(size)) {
		return nil, fmt.Errorf("mmap: file %q is too large", filename)
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)

	if err != nil {
		return nil, err
	}

	m := &mmap{data}

	runtime.SetFinalizer(m, (*mmap).Close)

	return m, nil
}
