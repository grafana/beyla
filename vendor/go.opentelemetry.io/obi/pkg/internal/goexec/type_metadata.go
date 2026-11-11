// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"errors"

	"go.opentelemetry.io/obi/internal/goversion"
)

// RuntimeTypeRegion locates the contiguous descriptor region used by Go 1.27+.
func RuntimeTypeRegion(ef *elf.File) (uint64, uint64, error) {
	version, _, err := getGoDetails(ef)
	if err != nil {
		return 0, 0, err
	}
	parsed, err := goversion.Parse(version)
	if err != nil {
		return 0, 0, err
	}
	abi, err := loadGoRuntimeABI(ef, parsed)
	if err != nil {
		return 0, 0, err
	}
	pcln := ef.Section(".gopclntab")
	if pcln == nil || abi.Moduledata.TypeDescLen == 0 {
		return 0, 0, errors.New("runtime type descriptor region unavailable")
	}
	relocs := buildRelocationInfo(ef)
	for _, candidate := range moduledataCandidates(ef, pcln.Addr, abi.Moduledata, relocs) {
		if _, ok := validateModuledata(ef, candidate, pcln.Addr, pcln.Size, abi.Moduledata, relocs); !ok {
			continue
		}
		base := resolveAddr(ef, candidate+abi.Moduledata.Types, relocs)
		size := readAddr(ef, candidate+abi.Moduledata.TypeDescLen)
		if base != 0 && size != 0 {
			return base, size, nil
		}
	}
	return 0, 0, errors.New("runtime type descriptor region not found")
}
