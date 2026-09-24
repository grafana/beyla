// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfconvenience // import "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
)

// BatchLookupAndDelete empties a full map in a handful of syscalls, where
// iterating costs two per entry.
const drainBatchLen = 1024

// drainOnce keeps the sweep to one per process. Each tracer opens the same pin
// and runs when its first matching executable is discovered, which can be long
// after start and at a different time for each, so without this the map would
// be emptied repeatedly at arbitrary points in the agent's life.
var drainOnce sync.Once

// DrainTraceContextMap empties the pinned traces_ctx_v1 map, whose key is a
// pid_tgid. Callers pass their own bpf2go-generated obi_ctx_info_t as V, so the
// value layout cannot drift from the C definition.
//
// The pin outlives the process, so entries written by a previous run survive
// into this one, and a run that is not populating never overwrites or deletes
// them: a reader would keep matching recycled pid_tgids against dead requests.
// Populating runs drain themselves through obi_ctx__del as requests complete,
// so only a non-populating run calls this.
//
// The pin is shared surface and records nothing about who wrote an entry, so
// this cannot tell a previous OBI run's entries from a co-resident writer's. It
// runs once, as early as a tracer can reach it.
func DrainTraceContextMap[V any](log *slog.Logger, m *ebpf.Map) {
	if m == nil {
		return
	}

	drainOnce.Do(func() { drainTraceContextMap[V](log, m) })
}

func drainTraceContextMap[V any](log *slog.Logger, m *ebpf.Map) {
	drained, err := drainMap[V](m)
	if err != nil {
		log.Warn("could not fully drain the trace context map, a reader may see stale context",
			"error", err, "drained_entries", drained)
		return
	}

	if drained > 0 {
		log.Info("drained stale entries from the pinned trace context map",
			"drained_entries", drained)
	}
}

// drainMap removes every entry, returning how many it removed. Kernels that
// reject the batch call fall back to iterate-and-delete; a partial batch drain
// leaves the rest of the map behind, so the fallback finishes the job rather
// than reporting a half-emptied map.
func drainMap[V any](m *ebpf.Map) (int, error) {
	drained, err := batchDrain[V](m)
	if err == nil {
		return drained, nil
	}

	iterated, err := iterateDrain[V](m)

	return drained + iterated, err
}

func batchDrain[V any](m *ebpf.Map) (int, error) {
	keys := make([]uint64, drainBatchLen)
	values := make([]V, drainBatchLen)

	drained := 0
	cursor := ebpf.MapBatchCursor{}

	for {
		n, err := m.BatchLookupAndDelete(&cursor, keys, values, nil)
		drained += n

		if err == nil {
			continue
		}

		// the kernel reports the end of the map as a missing key
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return drained, nil
		}

		return drained, err
	}
}

// iterateDrain collects the keys before deleting any of them: cilium/ebpf
// documents iterating a hash map while deleting from it as unsafe -- the walk
// can repeat a key or abort -- and this is the only path on kernels without
// batch map operations, which includes the supported 4.18 RHEL derivatives.
func iterateDrain[V any](m *ebpf.Map) (int, error) {
	var (
		key   uint64
		value V
	)

	var keys []uint64

	it := m.Iterate()
	for it.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := it.Err(); err != nil {
		return 0, err
	}

	drained := 0

	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return drained, err
		}
		drained++
	}

	return drained, nil
}
