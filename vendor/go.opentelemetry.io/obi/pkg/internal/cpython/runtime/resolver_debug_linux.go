// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"encoding/binary"
	"fmt"
)

// CPython 3.13-3.14 publish size and collecting as two uint64 debug words.
const inlineDebugGCSize = 16

type debugOffsetsDefinition struct {
	Cookie                string
	PrefixSize            int
	Version               int
	FreeThreaded          int
	RuntimeSize           int
	RuntimeFinalizing     int
	RuntimeInterpreters   int
	InterpretersMainDelta uint64
	InterpreterSize       int
	GCSize                int
	GCCollecting          int
}

// Bootstrap positions are pinned by the generator probe's _Static_asserts.
var debugOffsets = debugOffsetsDefinition{
	Cookie: "xdebugpy", PrefixSize: 96,
	Version: 8, FreeThreaded: 16,
	RuntimeSize: 24, RuntimeFinalizing: 32, RuntimeInterpreters: 40,
	InterpretersMainDelta: 8, InterpreterSize: 48,
	GCSize: 0, GCCollecting: 8,
}

func resolveDebugLayout(base layoutProfile, prefix, gc []byte) (layoutProfile, error) {
	if len(prefix) < debugOffsets.PrefixSize ||
		string(prefix[:len(debugOffsets.Cookie)]) != debugOffsets.Cookie {
		return layoutProfile{}, fmt.Errorf("%w: invalid debug offsets prefix", errUnsupportedLayout)
	}
	if base.debugInterpreterGCField < 0 || base.debugInterpreterGCField+8 > len(prefix) {
		return layoutProfile{}, fmt.Errorf("%w: missing interpreter GC offset", errUnsupportedLayout)
	}

	versionWord := debugWord(prefix, debugOffsets.Version)
	freeThreadedWord := debugWord(prefix, debugOffsets.FreeThreaded)
	if versionWord > uint64(^uint32(0)) || freeThreadedWord > 1 {
		return layoutProfile{}, fmt.Errorf("%w: invalid debug version or build mode", errUnsupportedLayout)
	}
	if uint32(versionWord) != base.version || freeThreadedWord != 0 {
		return layoutProfile{}, fmt.Errorf("%w: debug layout family mismatch", errUnsupportedLayout)
	}

	if len(gc) < inlineDebugGCSize {
		return layoutProfile{}, fmt.Errorf("%w: short GC debug offsets", errUnsupportedLayout)
	}

	resolved := base
	resolved.runtimeSize = debugWord(prefix, debugOffsets.RuntimeSize)
	resolved.runtimeFinalizing = debugWord(prefix, debugOffsets.RuntimeFinalizing)
	resolved.runtimeInterpretersMain = debugWord(prefix, debugOffsets.RuntimeInterpreters)
	resolved.interpreterSize = debugWord(prefix, debugOffsets.InterpreterSize)
	resolved.interpreterGC = debugWord(prefix, base.debugInterpreterGCField)
	resolved.gcSize = debugWord(gc, debugOffsets.GCSize)
	resolved.gcCollecting = debugWord(gc, debugOffsets.GCCollecting)
	if err := validateResolvedLayout(resolved, inlineDebugGCSize); err != nil {
		return layoutProfile{}, err
	}
	// _Py_DebugOffsets publishes interpreters.head; main is the next pointer.
	resolved.runtimeInterpretersMain += debugOffsets.InterpretersMainDelta
	return resolved, nil
}

func debugWord(values []byte, offset int) uint64 {
	return binary.LittleEndian.Uint64(values[offset : offset+8])
}

// validateResolvedLayout confines every published offset to its owning structure and the expected contiguous GC payload.
func validateResolvedLayout(profile layoutProfile, debugGCSize uint64) error {
	valid := profile.payloadSize > 0 && profile.payloadSize%8 == 0 &&
		profile.runtimeFinalizing != 0 && profile.runtimeInterpretersMain != 0 &&
		profile.debugGCOffset != 0 && profile.interpreterGC != 0 && profile.gcGenerationStats != 0 &&
		aligned8(profile.runtimeSize, profile.runtimeFinalizing, profile.runtimeInterpretersMain,
			profile.debugGCOffset, profile.interpreterSize, profile.interpreterGC,
			profile.gcSize, profile.gcGenerationStats) &&
		spanWithin(profile.runtimeSize, profile.runtimeFinalizing, 8) &&
		spanWithin(profile.runtimeSize, profile.runtimeInterpretersMain, debugOffsets.InterpretersMainDelta+8) &&
		spanWithin(profile.runtimeSize, profile.debugGCOffset, debugGCSize) &&
		spanWithin(profile.interpreterSize, profile.interpreterGC, profile.gcSize)
	valid = valid && profile.gcCollecting != 0 && profile.gcCollecting%4 == 0 &&
		spanWithin(profile.gcSize, profile.gcCollecting, 4)
	valid = valid &&
		spanWithin(profile.gcSize, profile.gcGenerationStats, uint64(profile.payloadSize)) &&
		profile.gcGenerationStats+uint64(profile.payloadSize) == profile.gcCollecting
	if !valid {
		return fmt.Errorf("%w: debug offsets exceed published structure sizes", errUnsupportedLayout)
	}
	return nil
}

func spanWithin(size, offset, width uint64) bool {
	return width <= size && offset <= size-width
}

func aligned8(values ...uint64) bool {
	for _, value := range values {
		if value%8 != 0 {
			return false
		}
	}
	return true
}

// elfAnalysis contains process-independent facts from one mapped ELF image.
type elfAnalysis struct {
	anchor         uint64
	versionAddress uint64
	profile        layoutProfile
	primaryProbe   GCCompletionProbe
	fallbackProbe  *GCCompletionProbe
}
