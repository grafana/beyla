// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import "os"

func openJSFileForScan(path string) (*os.File, bool, error) {
	// These scans are opportunistic. Without a portable nonblocking open,
	// skip them instead of using a check-then-open fallback that can block.
	return nil, false, nil
}
