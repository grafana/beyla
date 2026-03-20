// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"errors"
	"log/slog"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
)

func dlog(implementation string) *slog.Logger {
	return slog.With("component", "ebpf.FlowMapReader", "implementation", implementation)
}

type flowMapReader interface {
	lookupAndDeleteMap() (map[NetFlowId]*NetFlowMetrics, error)
}

func chooseMapReader(forcedType config.EBPFMapReader, flowMap *ebpf.Map, cacheMaxSize int, startTime uint64) flowMapReader {
	batchLen := defaultReadBatchLen
	possibleCPUs := ebpf.MustPossibleCPU()
	batch := &flowMapBatchReader{
		flowMap:      flowMap,
		cacheMaxSize: cacheMaxSize,
		possibleCPUs: possibleCPUs,
		lastReadNS:   startTime,
		cachedKeys:   make([]NetFlowId, batchLen),
		cachedValues: make([]NetFlowMetrics, batchLen*possibleCPUs),
	}
	legacy := &flowMapLegacyReader[*ebpf.MapIterator]{
		log:          dlog("legacy"),
		flowMap:      flowMap,
		cacheMaxSize: cacheMaxSize,
		lastReadNS:   startTime,
	}
	switch forcedType {
	case config.MapReaderLegacy:
		return legacy
	case config.MapReaderBatch:
		return batch
	default:
		return &flowMapReaderChooser[*ebpf.MapIterator]{
			batch:  batch,
			legacy: legacy,
		}
	}
}

// flowMapReaderChooser will choose, during first invocation to lookupAndDeleteMap,
// between the map Batch reader (if available) and the legacy iterator-based reader (fallback)
type flowMapReaderChooser[IT mapIterator] struct {
	working flowMapReader
	batch   *flowMapBatchReader
	legacy  *flowMapLegacyReader[IT]
}

func (ad *flowMapReaderChooser[IT]) lookupAndDeleteMap() (map[NetFlowId]*NetFlowMetrics, error) {
	if ad.working != nil {
		return ad.working.lookupAndDeleteMap()
	}
	log := dlog("auto")
	flows, err := ad.batch.lookupAndDeleteMap()
	if err == nil {
		log.Debug("batch map lookup is working")
		ad.working = ad.batch
		ad.batch, ad.legacy = nil, nil
		return flows, nil
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Warn("batch map lookup is not supported, falling back to legacy map iteration. This"+
			" is expected in RHEL8-based systems", "error", err)
		ad.working = ad.legacy
		ad.batch, ad.legacy = nil, nil
		return ad.working.lookupAndDeleteMap()
	}
	return flows, err
}
