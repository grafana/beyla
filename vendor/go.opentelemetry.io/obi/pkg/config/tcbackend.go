// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"fmt"
	"strings"
)

type TCBackend uint8

const (
	TCBackendTC = TCBackend(iota + 1)
	TCBackendTCX
	TCBackendAuto
)

func (b *TCBackend) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "tc":
		*b = TCBackendTC
		return nil
	case "tcx":
		*b = TCBackendTCX
		return nil
	case "auto":
		*b = TCBackendAuto
		return nil
	}

	return fmt.Errorf("invalid TCBakend value: '%s'", text)
}

func (b TCBackend) MarshalText() ([]byte, error) {
	switch b {
	case TCBackendTC:
		return []byte("tc"), nil
	case TCBackendTCX:
		return []byte("tcx"), nil
	case TCBackendAuto:
		return []byte("auto"), nil
	}

	return nil, fmt.Errorf("invalid TCBakend value: %d", b)
}

func (b TCBackend) Valid() bool {
	switch b {
	case TCBackendTC, TCBackendTCX, TCBackendAuto:
		return true
	}

	return false
}
