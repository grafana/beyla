// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package langtools // import "go.opentelemetry.io/obi/pkg/internal/langtools"

import "os"

// OpenMetadataFile opens a bounded regular file. A nil file with found set marks
// a path that exists but is unsafe or unusable as a metadata boundary.
func OpenMetadataFile(path string, _ int64) (*os.File, bool) {
	_, err := os.Lstat(path)
	return nil, !os.IsNotExist(err)
}
