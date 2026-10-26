// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"cmp"
	"errors"
	"slices"
)

// Only fixed-size decoded GC events are retained between NetTrace watermarks.
const maximumPendingGCEvents = 4096

type gcEventOrder struct {
	pending []gcRuntimeEvent
}

func (o *gcEventOrder) add(event gcRuntimeEvent) error {
	if len(o.pending) >= maximumPendingGCEvents {
		return errors.New("pending CLR GC events exceed ordering limit")
	}
	o.pending = append(o.pending, event)
	return nil
}

func (o *gcEventOrder) releaseBefore(watermark int64) ([]gcRuntimeEvent, error) {
	return o.release(watermark, false)
}

// finish releases pending events after the stream's explicit end marker.
func (o *gcEventOrder) finish() ([]gcRuntimeEvent, error) {
	return o.release(0, true)
}

func (o *gcEventOrder) release(watermark int64, final bool) ([]gcRuntimeEvent, error) {
	slices.SortStableFunc(o.pending, func(a, b gcRuntimeEvent) int {
		return cmp.Compare(a.timestamp, b.timestamp)
	})
	// Events at the watermark can still arrive from another thread.
	count := 0
	for count < len(o.pending) && (final || o.pending[count].timestamp < watermark) {
		if count > 0 && o.pending[count].timestamp == o.pending[count-1].timestamp &&
			o.pending[count].threadID != o.pending[count-1].threadID {
			return nil, errors.New("ambiguous CLR GC event order across threads")
		}
		count++
	}
	released := slices.Clone(o.pending[:count])
	o.pending = slices.Delete(o.pending, 0, count)
	return released, nil
}
