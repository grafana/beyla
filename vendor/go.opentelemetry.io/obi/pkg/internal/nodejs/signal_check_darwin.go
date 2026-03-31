// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import "debug/elf"

// hasUserSIGUSR1Handler is a no-op on non-Linux platforms.
func hasUserSIGUSR1Handler(_ int, _ *elf.File) signalCheckResult {
	return signalCheckNotFound
}

// sourceHasSIGUSR1Reference is a no-op on non-Linux platforms.
func sourceHasSIGUSR1Reference(_ int) bool {
	return false
}
