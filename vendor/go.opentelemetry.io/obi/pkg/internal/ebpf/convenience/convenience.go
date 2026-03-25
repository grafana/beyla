// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfconvenience // import "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

// This file contains convenience functions around the cilum/ebpf
// CollectionSpec.Variables API.
// This wrapper has been deprecated in the main cilium/ebpf codebase.

const PinInternal = ebpf.PinType(100)

func roundToNearestMultiple(x, n uint32) uint32 {
	if x < n {
		return n
	}

	if x%n == 0 {
		return x
	}

	return (x + n/2) / n * n
}

// RingBuf map types must be a multiple of os.Getpagesize()
func alignMaxEntriesIfRingBuf(m *ebpf.MapSpec) {
	if m.Type == ebpf.RingBuf {
		m.MaxEntries = roundToNearestMultiple(m.MaxEntries, uint32(os.Getpagesize()))
	}
}

// ResolveMaps sets up internal maps and ensures sane max entries values
func ResolveMaps(spec *ebpf.CollectionSpec, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex) (*ebpf.CollectionOptions, error) {
	collOpts := ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{}}

	mu.Lock()
	defer mu.Unlock()

	for k, v := range spec.Maps {
		alignMaxEntriesIfRingBuf(v)

		if v.Pinning != PinInternal {
			continue
		}

		v.Pinning = ebpf.PinNone
		internalMap := sharedMaps[k]

		var err error

		if internalMap == nil {
			internalMap, err = ebpf.NewMap(v)
			if err != nil {
				return nil, fmt.Errorf("failed to load shared map: %w", err)
			}

			sharedMaps[k] = internalMap
			runtime.SetFinalizer(internalMap, (*ebpf.Map).Close)
		}

		collOpts.MapReplacements[k] = internalMap
	}

	return &collOpts, nil
}

// LoadSpec loads a BPF collection spec into the provided objects, handling
// constant rewriting, PinInternal map resolution, and bpffs pin path setup.
// Notes about some parameters:
// - constants: optional map of BPF constants to rewrite (may be nil)
// - sharedMaps: map store for PinInternal maps, shared across specs within the same agent
// - pinPath: bpffs pin path for PinByName maps (empty string to skip)
func LoadSpec(spec *ebpf.CollectionSpec, objects any, constants map[string]any, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, pinPath string) error {
	if constants != nil {
		if err := RewriteConstants(spec, constants); err != nil {
			return fmt.Errorf("rewriting BPF constants: %w", err)
		}
	}

	collOpts, err := ResolveMaps(spec, sharedMaps, mu)
	if err != nil {
		return fmt.Errorf("resolving maps: %w", err)
	}

	collOpts.Programs = ebpf.ProgramOptions{LogSizeStart: 640 * 1024}
	collOpts.Maps = ebpf.MapOptions{PinPath: pinPath}

	if err := spec.LoadAndAssign(objects, collOpts); err != nil {
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	return nil
}

// MissingConstantsError is returned by [ebpf.CollectionSpec.RewriteConstants].
type MissingConstantsError struct {
	// The constants missing from .rodata.
	Constants []string
}

func (m *MissingConstantsError) Error() string {
	return "some constants are missing from .rodata: " + strings.Join(m.Constants, ", ")
}

// RewriteConstants replaces the value of multiple constants.
//
// The constant must be defined like so in the C program:
//
//	volatile const type foobar;
//	volatile const type foobar = default;
//
// Replacement values must be of the same length as the C sizeof(type).
// If necessary, they are marshaled according to the same rules as
// map values.
//
// From Linux 5.5 the verifier will use constants to eliminate dead code.
//
// Returns an error wrapping [MissingConstantsError] if a constant doesn't exist.
func RewriteConstants(cs *ebpf.CollectionSpec, consts map[string]any) error {
	var missing []string
	for n, c := range consts {
		v, ok := cs.Variables[n]
		if !ok {
			missing = append(missing, n)
			continue
		}

		if !v.Constant() {
			return fmt.Errorf("variable %s is not a constant", n)
		}

		if err := v.Set(c); err != nil {
			return fmt.Errorf("rewriting constant %s: %w", n, err)
		}
	}

	if len(missing) != 0 {
		return fmt.Errorf("rewrite constants: %w", &MissingConstantsError{Constants: missing})
	}

	return nil
}
