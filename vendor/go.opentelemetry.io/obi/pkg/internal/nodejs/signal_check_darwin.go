// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	"errors"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// nodeSymbols is empty on non-Linux platforms.
type nodeSymbols struct{}

// readNodeSymbols is a no-op on non-Linux platforms.
func readNodeSymbols(_ *elf.File) nodeSymbols {
	return nodeSymbols{}
}

// sendSIGUSR1 is a no-op on non-Linux platforms.
var sendSIGUSR1 = func(_ *procs.ProcessHandle) error {
	return errors.New("signaling a pinned process is only supported on Linux")
}

// sigusr1Disposition is a no-op on non-Linux platforms.
func sigusr1Disposition(_ int) signalDisposition {
	return signalDispositionHandled
}

// hasUserSIGUSR1Handler is a no-op on non-Linux platforms.
func hasUserSIGUSR1Handler(_ int, _ *elf.File, _ nodeSymbols) signalCheckResult {
	return signalCheckNotFound
}

// sourceHasSIGUSR1Reference is a no-op on non-Linux platforms.
func sourceHasSIGUSR1Reference(_ int) bool {
	return false
}
