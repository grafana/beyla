package ebpfcommon

import (
	"fmt"
	"io"
	"log/slog"
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

func (libs InstrumentedLibsT) RemoveRef(id uint64) (*LibModule, error) {
	module := libs.Find(id)

	if module == nil {
		return nil, fmt.Errorf("attempt to remove reference of unknown module: %d", id)
	}

	if module.References == 0 {
		return module, fmt.Errorf("attempt to remove reference of unreferenced module: %d", id)
	}

	module.References--

	if module.References == 0 {
		for _, closer := range module.Closers {
			if err := closer.Close(); err != nil {
				slog.Debug("failed to close resource", "closer", closer, "error", err)
			}
		}

		delete(libs, id)
	}

	return module, nil
}
