package ebpfcommon

import (
	"fmt"
	"io"
	"log/slog"
)

type BinModule struct {
	References uint64
	Closers    []io.Closer
}

// Hold onto Linux inode numbers of files that are already instrumented, e.g. libssl.so.3
type InstrumentedBins map[uint64]*BinModule

func (bins InstrumentedBins) At(id uint64) *BinModule {
	module, ok := bins[id]

	if !ok {
		module = &BinModule{References: 0}
		bins[id] = module
	}

	return module
}

func (bins InstrumentedBins) Find(id uint64) *BinModule {
	module, ok := bins[id]

	if ok {
		return module
	}

	return nil
}

func (bins InstrumentedBins) AddRef(id uint64) *BinModule {
	module := bins.At(id)
	module.References++

	return module
}

func (bins InstrumentedBins) RemoveRef(id uint64) (*BinModule, error) {
	module := bins.Find(id)

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

		delete(bins, id)
	}

	return module, nil
}
