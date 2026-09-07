// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !amd64

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"debug/elf"
	"fmt"
)

var errPrivateCollectorProbeUnsupported = fmt.Errorf("%w: private CPython collector probes require amd64", errUnsupportedLayout)

// findPrivateCollectorProbe fails closed because private collector probes support amd64 only.
func findPrivateCollectorProbe(*elf.File) (GCCompletionProbe, error) {
	return GCCompletionProbe{}, errPrivateCollectorProbeUnsupported
}
