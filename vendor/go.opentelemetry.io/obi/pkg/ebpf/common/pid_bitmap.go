// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// PIDBitmapWords is the size of a pid-indexed BPF bitmap such as valid_pids (bpf/pid/pid.h)
const PIDBitmapWords = uint32(BpfValidPidsSizeK_validPidsWords)

// PIDBitmap mirrors a pid-indexed BPF bitmap: one bit per pid, as OBI's /proc numbers it
type PIDBitmap struct {
	mu sync.Mutex
	// the words as last written to the BPF map
	words []uint64
}

// Rebuild sets exactly the bits of the filter's pids of the given types and returns the added ones
func (b *PIDBitmap) Rebuild(m *ebpf.Map, filter ServiceFilter, types PIDType, log *slog.Logger) ([]app.PID, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.words == nil {
		b.words = make([]uint64, PIDBitmapWords)
	}

	// under the lock, or an older list can be written last
	pids := filter.ProcPIDs(types)

	want := map[uint32]uint64{}
	var added []app.PID
	for _, pid := range pids {
		if uint64(pid) >= uint64(PIDBitmapWords)*64 {
			log.Warn("pid beyond the BPF PID filter, it won't be instrumented", "pid", pid)
			continue
		}
		want[uint32(pid/64)] |= 1 << (pid % 64)
		if !b.contains(pid) {
			added = append(added, pid)
		}
	}

	for word, bits := range b.words {
		if _, ok := want[uint32(word)]; bits != 0 && !ok {
			want[uint32(word)] = 0
		}
	}

	written := 0
	var err error
	for word, bits := range want {
		if b.words[word] == bits {
			continue
		}
		if err = m.Put(word, bits); err != nil {
			err = fmt.Errorf("writing word %d of the BPF PID filter: %w", word, err)
			break
		}
		b.words[word] = bits
		written++
	}
	log.Debug("BPF PID filter rebuilt", "pids", len(pids), "wordsWritten", written)

	return slices.DeleteFunc(added, func(pid app.PID) bool { return !b.contains(pid) }), err
}

func (b *PIDBitmap) contains(pid app.PID) bool {
	word := uint64(pid) / 64
	return word < uint64(len(b.words)) && b.words[word]&(1<<(pid%64)) != 0
}
