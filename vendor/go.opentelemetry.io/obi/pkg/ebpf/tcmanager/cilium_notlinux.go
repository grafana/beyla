// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package tcmanager // import "go.opentelemetry.io/obi/pkg/ebpf/tcmanager"

import (
	"go.opentelemetry.io/obi/pkg/config"
)

func EnsureCiliumCompatibility(_ config.TCBackend) error {
	return nil
}
