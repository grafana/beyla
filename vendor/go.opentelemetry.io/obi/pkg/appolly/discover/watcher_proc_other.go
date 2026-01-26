// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package discover

// placeholder files to allow local compilation/unit testing in non-linux environments

func currentTime() uint64 {
	return 0
}
