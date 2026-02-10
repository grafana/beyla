// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"fmt"
	"strings"
)

type CudaMode uint8

const (
	CudaModeAuto = CudaMode(iota + 1)
	CudaModeOn
	CudaModeOff
)

func (b *CudaMode) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "on":
		*b = CudaModeOn
		return nil
	case "off":
		*b = CudaModeOff
		return nil
	case "auto":
		*b = CudaModeAuto
		return nil
	}

	return fmt.Errorf("invalid Cuda instrumentation mode value: '%s'", text)
}

func (b CudaMode) MarshalText() ([]byte, error) {
	switch b {
	case CudaModeOn:
		return []byte("on"), nil
	case CudaModeOff:
		return []byte("off"), nil
	case CudaModeAuto:
		return []byte("auto"), nil
	}

	return nil, fmt.Errorf("invalid Cuda instrumentation mode value: %d", b)
}

func (b CudaMode) Valid() bool {
	switch b {
	case CudaModeOn, CudaModeOff, CudaModeAuto:
		return true
	}

	return false
}
