// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	procSelfFDInfo  = "/proc/self/fdinfo"
	fdinfoProgramID = "prog_id:"
)

func ownedProgramIDs(fdinfoDir string) ([]ebpf.ProgramID, error) {
	entries, err := os.ReadDir(fdinfoDir)
	if err != nil {
		return nil, err
	}

	ids := make(map[ebpf.ProgramID]struct{})
	var readErr error
	for _, entry := range entries {
		// The fdinfo of a program, and of a link, carries the program ID.
		id, ok, err := fdinfoID(filepath.Join(fdinfoDir, entry.Name()), fdinfoProgramID)
		if err != nil {
			// The readable descriptors are still returned; the error marks the list incomplete.
			readErr = errors.Join(readErr, err)
			continue
		}
		if ok {
			ids[ebpf.ProgramID(id)] = struct{}{}
		}
	}

	return slices.Sorted(maps.Keys(ids)), readErr
}

func fdinfoID(path, key string) (uint32, bool, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// A descriptor closed after its directory was read is skipped.
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}

	for line := range strings.Lines(string(content)) {
		value, found := strings.CutPrefix(line, key)
		if !found {
			continue
		}

		id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
		return uint32(id), err == nil, nil
	}

	return 0, false, nil
}
