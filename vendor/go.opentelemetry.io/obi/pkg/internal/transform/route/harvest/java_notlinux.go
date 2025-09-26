// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package harvest

import (
	"io"
	"log/slog"
)

var jvmAttachFunc = func(_ int, _ []string, _ *slog.Logger) (io.ReadCloser, error) {
	return nil, nil
}
