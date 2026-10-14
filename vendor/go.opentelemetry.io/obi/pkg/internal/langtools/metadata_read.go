// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package langtools // import "go.opentelemetry.io/obi/pkg/internal/langtools"

import (
	"fmt"
	"io"
)

// ReadMetadataFile safely reads a bounded regular metadata file. A nil data
// slice with found set marks a path that exists but could not be read safely.
func ReadMetadataFile(path string, maxBytes int64) ([]byte, bool, error) {
	file, found := OpenMetadataFile(path, maxBytes)
	if file == nil {
		return nil, found, nil
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(data)) > maxBytes {
		return nil, true, fmt.Errorf("metadata file %s exceeds %d bytes", path, maxBytes)
	}
	return data, true, nil
}
