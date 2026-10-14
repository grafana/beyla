// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"
	"io"
)

type LibModule struct {
	References uint64
	Closers    []io.Closer
}

// Hold onto Linux inode numbers of files that are already instrumented, e.g. libssl.so.3
type InstrumentedLibsT map[uint64]*LibModule

func (libs InstrumentedLibsT) At(id uint64) *LibModule {
	module, ok := libs[id]

	if !ok {
		module = &LibModule{References: 0}
		libs[id] = module
	}

	return module
}

func (libs InstrumentedLibsT) Find(id uint64) *LibModule {
	module, ok := libs[id]

	if ok {
		return module
	}

	return nil
}

func (libs InstrumentedLibsT) AddRef(id uint64) *LibModule {
	module := libs.At(id)
	module.References++

	return module
}

// RemoveRef reports whether it removed the last reference. The module is then forgotten and
// closing its Closers is left to the caller, so it can happen outside the caller's lock
func (libs InstrumentedLibsT) RemoveRef(id uint64) (*LibModule, bool, error) {
	module := libs.Find(id)

	if module == nil {
		return nil, false, fmt.Errorf("attempt to remove reference of unknown module: %d", id)
	}

	if module.References == 0 {
		return module, false, fmt.Errorf("attempt to remove reference of unreferenced module: %d", id)
	}

	module.References--

	if module.References > 0 {
		return module, false, nil
	}

	delete(libs, id)

	return module, true, nil
}
