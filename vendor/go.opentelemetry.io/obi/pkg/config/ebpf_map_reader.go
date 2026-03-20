// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"fmt"
	"strings"
)

type EBPFMapReader uint8

const (
	MapReaderAuto = EBPFMapReader(iota)
	MapReaderBatch
	MapReaderLegacy
)

func (b *EBPFMapReader) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(strings.ToLower(string(text))) {
	case "batch":
		*b = MapReaderBatch
		return nil
	case "legacy":
		*b = MapReaderLegacy
		return nil
	case "", "auto":
		*b = MapReaderAuto
		return nil
	}
	return fmt.Errorf("invalid EBPFMapReader value: %s", text)
}

func (b EBPFMapReader) MarshalText() ([]byte, error) {
	switch b {
	case MapReaderBatch:
		return []byte("batch"), nil
	case MapReaderLegacy:
		return []byte("legacy"), nil
	case MapReaderAuto:
		return []byte("auto"), nil
	}
	return nil, fmt.Errorf("invalid EBPFMapReader value: %d", b)
}

func (b EBPFMapReader) Valid() bool {
	switch b {
	case MapReaderBatch, MapReaderLegacy, MapReaderAuto:
		return true
	}
	return false
}
