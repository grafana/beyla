// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"fmt"
	"math"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type gcFragmentation struct {
	clrInstanceID *uint16
	full          *gcHeapCollection
	ephemeral     *gcHeapCollection
	// The latest completed collection can have an older ID than an overlapping GC.
	latest  *gcHeapCollection
	batches map[uint64]*gcHeapBatch
}

// Completion and heap history can arrive in either order.
type gcHeapCollection struct {
	identity      gcCollectionEvent
	completed     bool
	fragmentation *[runtimemetrics.DotnetHeapGenerationCount]uint64
}

type gcHeapBatch struct {
	collection    *gcHeapCollection
	heapCount     uint32
	seen          map[uint32]struct{}
	fragmentation [runtimemetrics.DotnetHeapGenerationCount]uint64
}

func (f *gcFragmentation) observe(event gcRuntimeEvent) error {
	switch event.eventID {
	case clrGCStartEventID:
		return f.start(event.collection)
	case clrGCEndEventID:
		return f.complete(event.collection)
	case clrGCGlobalHeapHistoryEventID:
		return f.beginHistory(event.threadID, event.globalHistory)
	case clrGCPerHeapHistoryEventID:
		return f.addHeapHistory(event.threadID, event.perHeapHistory)
	default:
		return fmt.Errorf("unexpected CLR GC event ID: %d", event.eventID)
	}
}

func (f *gcFragmentation) snapshot() [runtimemetrics.DotnetHeapGenerationCount]*int64 {
	var values [runtimemetrics.DotnetHeapGenerationCount]*int64
	if f.latest == nil || f.latest.fragmentation == nil {
		return values
	}
	for generation, fragmentation := range f.latest.fragmentation {
		value := int64(fragmentation)
		values[generation] = &value
	}
	return values
}

func (b *gcHeapBatch) add(history gcPerHeapHistory) error {
	if history.clrInstanceID != b.collection.identity.clrInstanceID {
		return fmt.Errorf("CLR GC heap instance %d does not match collection instance %d", history.clrInstanceID, b.collection.identity.clrInstanceID)
	}
	if _, exists := b.seen[history.heapIndex]; exists {
		return fmt.Errorf("duplicate CLR GC heap index: %d", history.heapIndex)
	}
	if uint32(len(b.seen)) >= b.heapCount {
		return fmt.Errorf("CLR GC heap records exceed expected count: %d", b.heapCount)
	}
	// Validate all sums before changing the batch.
	next := b.fragmentation
	for generation, value := range history.fragmentation {
		if value > math.MaxInt64-next[generation] {
			return fmt.Errorf("CLR GC fragmentation exceeds exporter range for generation %d", generation)
		}
		next[generation] += value
	}
	if b.seen == nil {
		b.seen = make(map[uint32]struct{})
	}
	b.seen[history.heapIndex] = struct{}{}
	b.fragmentation = next
	return nil
}

func (f *gcFragmentation) start(identity gcCollectionEvent) error {
	if f.clrInstanceID != nil && *f.clrInstanceID != identity.clrInstanceID {
		return fmt.Errorf("CLR GC instance changed from %d to %d", *f.clrInstanceID, identity.clrInstanceID)
	}
	current := f.ephemeral
	if identity.depth == runtimemetrics.DotnetGCGenerationCount-1 {
		current = f.full
	}
	if current != nil && (!current.completed || current.fragmentation == nil) {
		return fmt.Errorf("overlapping CLR GC collections at depth %d", identity.depth)
	}
	if f.clrInstanceID == nil {
		instanceID := identity.clrInstanceID
		f.clrInstanceID = &instanceID
	}
	collection := &gcHeapCollection{identity: identity}
	if identity.depth == runtimemetrics.DotnetGCGenerationCount-1 {
		f.full = collection
	} else {
		f.ephemeral = collection
	}
	return nil
}

func (f *gcFragmentation) complete(identity gcCollectionEvent) error {
	if f.clrInstanceID != nil && *f.clrInstanceID != identity.clrInstanceID {
		return fmt.Errorf("CLR GC instance changed from %d to %d", *f.clrInstanceID, identity.clrInstanceID)
	}
	collection := f.ephemeral
	if identity.depth == runtimemetrics.DotnetGCGenerationCount-1 {
		collection = f.full
	}
	if collection == nil || collection.identity != identity {
		// Attachment can miss the start of a collection that completes afterward.
		f.latest = nil
		return nil
	}
	if collection.completed {
		return fmt.Errorf("duplicate CLR GC completion for collection %d", identity.count)
	}
	collection.completed = true
	f.latest = collection
	return nil
}

func (f *gcFragmentation) beginHistory(threadID uint64, history gcGlobalHeapHistory) error {
	const maximumGCHeaps = 4096
	if history.heapCount == 0 || history.heapCount > maximumGCHeaps {
		return fmt.Errorf("CLR GC heap count outside supported range: %d", history.heapCount)
	}
	if f.batches[threadID] != nil {
		return fmt.Errorf("overlapping CLR GC heap histories on thread %d", threadID)
	}
	collection := f.ephemeral
	if history.depth == runtimemetrics.DotnetGCGenerationCount-1 {
		collection = f.full
	}
	if collection == nil {
		return nil
	}
	if collection.identity.depth != history.depth || collection.identity.clrInstanceID != history.clrInstanceID {
		return fmt.Errorf("CLR GC heap history does not match collection %d", collection.identity.count)
	}
	if collection.fragmentation != nil {
		return fmt.Errorf("duplicate CLR GC heap history for collection %d", collection.identity.count)
	}
	for _, batch := range f.batches {
		if batch.collection == collection {
			return fmt.Errorf("duplicate CLR GC heap history for collection %d", collection.identity.count)
		}
	}
	if f.batches == nil {
		f.batches = make(map[uint64]*gcHeapBatch)
	}
	// Global and per-heap histories for a collection share an emitting thread.
	f.batches[threadID] = &gcHeapBatch{collection: collection, heapCount: history.heapCount}
	return nil
}

func (f *gcFragmentation) addHeapHistory(threadID uint64, history gcPerHeapHistory) error {
	batch := f.batches[threadID]
	if batch == nil {
		// Attachment can miss the global history that starts this batch.
		return nil
	}
	if err := batch.add(history); err != nil {
		return err
	}
	if uint32(len(batch.seen)) == batch.heapCount {
		fragmentation := batch.fragmentation
		batch.collection.fragmentation = &fragmentation
		delete(f.batches, threadID)
	}
	return nil
}
