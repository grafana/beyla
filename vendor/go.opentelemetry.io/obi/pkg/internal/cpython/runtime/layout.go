// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/grafana/go-offsets-tracker/pkg/offsets"
)

const (
	cpythonReleaseLevelFinal = 0xf // CPython's PY_RELEASE_LEVEL_FINAL value.
	pySsizeTSize             = 8
	inlineRecordSize         = 3 * pySsizeTSize
	inlinePayloadSize        = 3 * inlineRecordSize
)

// layoutProfile describes one supported CPython layout family.
type layoutProfile struct {
	version                 uint32
	runtimeSize             uint64
	runtimeFinalizing       uint64
	runtimeInterpretersMain uint64
	interpreterSize         uint64
	interpreterGC           uint64
	gcSize                  uint64
	gcGenerationStats       uint64
	gcCollecting            uint64
	payloadSize             int
	debugGCOffset           uint64
	debugInterpreterGCField int
}

//go:embed offsets.json
var embeddedOffsets []byte

var layoutOffsets, supportedVersions = mustReadLayoutData(embeddedOffsets)

func mustReadLayoutData(data []byte) (*offsets.Track, map[string]uint8) {
	track, supported, err := readLayoutData(data)
	if err != nil {
		panic(fmt.Sprintf("reading embedded CPython offsets: %v", err))
	}
	return track, supported
}

func readLayoutData(data []byte) (*offsets.Track, map[string]uint8, error) {
	track, err := offsets.Read(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	metadata := struct {
		Supported map[string]uint8 `json:"supported"`
	}{}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, nil, err
	}
	return track, metadata.Supported, nil
}

// selectLayout accepts only stable, non-free-threaded releases covered by the generated offset ranges.
func selectLayout(version uint32, freeThreaded bool) (layoutProfile, bool) {
	parsed := versionFromHex(version)
	if freeThreaded || parsed.major != 3 {
		return layoutProfile{}, false
	}
	if parsed.releaseLevel == cpythonReleaseLevelFinal {
		newest, ok := supportedVersions[fmt.Sprintf("%d.%d", parsed.major, parsed.minor)]
		if !ok || parsed.micro > newest {
			return layoutProfile{}, false
		}
	}

	profile := layoutProfile{version: version}
	versionString := parsed.String()
	switch {
	case parsed.minor >= 9 && parsed.minor <= 12 && parsed.releaseLevel == cpythonReleaseLevelFinal:
		profile.payloadSize = inlinePayloadSize
		if !loadLegacyOffsets(&profile, versionString) {
			return layoutProfile{}, false
		}
	case parsed.minor >= 13 && parsed.minor <= 14 && parsed.releaseLevel == cpythonReleaseLevelFinal:
		profile.payloadSize = inlinePayloadSize
		if !loadDebugOffsets(&profile, versionString) {
			return layoutProfile{}, false
		}
		var ok bool
		profile.gcGenerationStats, ok = requiredOffset("_gc_runtime_state", "generation_stats", versionString)
		if !ok {
			return layoutProfile{}, false
		}
	default:
		return layoutProfile{}, false
	}

	return profile, true
}

// loadLegacyOffsets loads all required offsets from the generated table for
// CPython 3.9-3.12, where _Py_DebugOffsets does not expose the GC layout OBI needs.
func loadLegacyOffsets(profile *layoutProfile, version string) bool {
	var ok bool
	if profile.runtimeFinalizing, ok = requiredOffset("_PyRuntimeState", "_finalizing", version); !ok {
		return false
	}
	if profile.runtimeInterpretersMain, ok = requiredOffset("_PyRuntimeState", "interpreters.main", version); !ok {
		return false
	}
	if profile.interpreterGC, ok = requiredOffset("PyInterpreterState", "gc", version); !ok {
		return false
	}
	if profile.gcGenerationStats, ok = requiredOffset("_gc_runtime_state", "generation_stats", version); !ok {
		return false
	}
	profile.gcCollecting, ok = requiredOffset("_gc_runtime_state", "collecting", version)
	return ok
}

func loadDebugOffsets(profile *layoutProfile, version string) bool {
	var ok bool
	if profile.debugGCOffset, ok = requiredOffset("_Py_DebugOffsets", "gc", version); !ok {
		return false
	}
	offset, ok := requiredOffset("_Py_DebugOffsets", "interpreter_state.gc", version)
	profile.debugInterpreterGCField = int(offset)
	return ok
}

func requiredOffset(structure, field, version string) (uint64, bool) {
	offset, ok := layoutOffsets.Find(structure, field, version)
	return offset, ok && offset != 0 && offset%8 == 0
}

type pythonVersion struct {
	major        uint8
	minor        uint8
	micro        uint8
	releaseLevel uint8
	serial       uint8
}

func versionFromHex(version uint32) pythonVersion {
	return pythonVersion{
		major:        uint8(version >> 24),
		minor:        uint8(version >> 16),
		micro:        uint8(version >> 8),
		releaseLevel: uint8(version>>4) & 0xf,
		serial:       uint8(version) & 0xf,
	}
}

func (v pythonVersion) String() string {
	base := fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.micro)
	switch v.releaseLevel {
	case 0xa:
		return fmt.Sprintf("%sa%d", base, v.serial)
	case 0xb:
		return fmt.Sprintf("%sb%d", base, v.serial)
	case 0xc:
		return fmt.Sprintf("%src%d", base, v.serial)
	default:
		return base
	}
}
