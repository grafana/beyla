// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package discover

func (ta *TraceAttacher) init() error {
	return nil
}

func (ta *TraceAttacher) close() {}
