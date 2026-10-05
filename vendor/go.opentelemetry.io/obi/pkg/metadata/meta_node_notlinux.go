// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"context"
)

// permits compilation in non-linux environments
func linuxLocalFetcher(_ context.Context) (NodeMeta, error) {
	return NodeMeta{}, nil
}
