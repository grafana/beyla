// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"strings"

	trackeroffsets "github.com/grafana/go-offsets-tracker/pkg/offsets"

	"go.opentelemetry.io/obi/internal/goabi"
	"go.opentelemetry.io/obi/internal/goversion"
)

func loadGoRuntimeABI(ef *elf.File, targetVersion goversion.Version) (goabi.ABI, error) {
	return resolveGoRuntimeABI(
		func() (goabi.ABI, error) {
			data, err := ef.DWARF()
			if err != nil {
				return goabi.ABI{}, err
			}
			return goabi.Extract(data, targetVersion)
		},
		func() (goabi.ABI, error) {
			return loadGeneratedGoRuntimeABI(targetVersion)
		},
	)
}

func resolveGoRuntimeABI(
	dynamic func() (goabi.ABI, error),
	generated func() (goabi.ABI, error),
) (goabi.ABI, error) {
	abi, dynamicErr := dynamic()
	if dynamicErr == nil {
		return abi, nil
	}
	abi, generatedErr := generated()
	if generatedErr == nil {
		return abi, nil
	}
	return goabi.ABI{}, fmt.Errorf(
		"go runtime ABI unavailable: %w",
		errors.Join(
			fmt.Errorf("DWARF discovery: %w", dynamicErr),
			fmt.Errorf("generated fallback: %w", generatedErr),
		),
	)
}

func loadGeneratedGoRuntimeABI(targetVersion goversion.Version) (goabi.ABI, error) {
	track, err := trackeroffsets.Read(bytes.NewBufferString(prefetchedOffsets))
	if err != nil {
		return goabi.ABI{}, fmt.Errorf("reading generated Go ABI facts: %w", err)
	}
	return goabi.FromLookup(targetVersion, func(requirement goabi.Requirement) (uint64, error) {
		return generatedABIFact(track, requirement.OutputType, requirement.OutputField, targetVersion)
	})
}

func generatedABIFact(
	track *trackeroffsets.Track,
	typeName string,
	factName string,
	targetVersion goversion.Version,
) (uint64, error) {
	fields, ok := track.Data[typeName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI type %s", typeName)
	}
	fact, ok := fields[factName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s", typeName, factName)
	}

	covered, err := generatedVersionCovered(targetVersion, fact.Versions.Oldest, fact.Versions.Newest)
	if err != nil {
		return 0, fmt.Errorf("invalid generated Go ABI coverage for %s.%s: %w", typeName, factName, err)
	}
	if !covered {
		return 0, fmt.Errorf("runtime ABI is not generated for %s", targetVersion.String())
	}

	value, ok := track.Find(typeName, factName, targetVersion.Release())
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s for %s", typeName, factName, targetVersion.String())
	}
	return value, nil
}

func generatedVersionCovered(targetVersion goversion.Version, oldestValue, newestValue string) (bool, error) {
	if strings.Contains(targetVersion.String(), "-") {
		return false, nil
	}
	oldest, err := goversion.Parse(oldestValue)
	if err != nil {
		return false, err
	}
	newest, err := goversion.Parse(newestValue)
	if err != nil {
		return false, err
	}
	return targetVersion.Compare(oldest) >= 0 && targetVersion.Compare(newest) <= 0, nil
}
