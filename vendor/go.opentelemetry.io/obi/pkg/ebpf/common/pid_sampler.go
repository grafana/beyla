// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

// ratioKeySpace is the number of TraceIDRatioBased keys: the 63 bits left of a
// trace id's last 8 bytes once the OpenTelemetry Go SDK shifts them right by one
const ratioKeySpace = 1 << 63

// PIDSamplers keeps the namespace keys needed to remove samplers after processes exit.
type PIDSamplers struct {
	mu   sync.Mutex
	keys map[app.PID]BpfPidInfoT
}

// pidSampler returns the pid_samplers entry (bpf/maps/pid_samplers.h) of a
// process with the service's sampler, or the global one when it has none. The
// default parentbased_always_on needs no entry.
func pidSampler(service, global *services.SamplerConfig) (BpfSamplerT, bool) {
	cfg := service
	if cfg == nil {
		cfg = global
	}
	if cfg == nil {
		return BpfSamplerT{}, false
	}

	ratio, parentBased := cfg.TraceIDRatio()
	if parentBased && ratio >= 1 {
		return BpfSamplerT{}, false
	}

	sampler := BpfSamplerT{Threshold: ratioThreshold(ratio)}
	if parentBased {
		sampler.ParentBased = 1
	}

	return sampler, true
}

// ratioThreshold is the threshold of the OpenTelemetry Go SDK TraceIDRatioBased sampler
func ratioThreshold(ratio float64) uint64 {
	switch {
	case ratio >= 1:
		return ratioKeySpace
	case ratio <= 0:
		return 0
	default:
		return uint64(ratio * ratioKeySpace)
	}
}

// Write sets the sampler eBPF applies to the traces the process starts.
func (s *PIDSamplers) Write(m *ebpf.Map, pid app.PID, ns uint32, service, global *services.SamplerConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sampler, ok := pidSampler(service, global)
	if !ok {
		return s.delete(m, pid)
	}

	key, err := pidSamplerKey(pid, ns)
	if err != nil {
		return err
	}
	if old, exists := s.keys[pid]; exists && old != key {
		if err := s.delete(m, pid); err != nil {
			return err
		}
	}
	if err := m.Put(key, sampler); err != nil {
		return err
	}
	if s.keys == nil {
		s.keys = map[app.PID]BpfPidInfoT{}
	}
	s.keys[pid] = key
	return nil
}

// Delete leaves the process with the default sampler.
func (s *PIDSamplers) Delete(m *ebpf.Map, pid app.PID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.delete(m, pid)
}

func (s *PIDSamplers) delete(m *ebpf.Map, pid app.PID) error {
	key, ok := s.keys[pid]
	if !ok {
		return nil
	}
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	delete(s.keys, pid)
	return nil
}

func pidSamplerKey(pid app.PID, ns uint32) (BpfPidInfoT, error) {
	pids, err := readNamespacePIDs(pid)
	if err != nil {
		return BpfPidInfoT{}, fmt.Errorf("reading namespaced PIDs: %w", err)
	}
	if len(pids) != 0 {
		pid = pids[len(pids)-1]
	}
	return BpfPidInfoT{UserPid: uint32(pid), Ns: ns}, nil
}
