// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"errors"
	"os"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

type ProcessHandle struct{}

func OpenProcessHandle(app.PID, uint64) (*ProcessHandle, error) {
	return nil, errors.New("stable process handles are only supported on Linux")
}

func (*ProcessHandle) PID() app.PID                       { return 0 }
func (*ProcessHandle) Open(string, int) (*os.File, error) { return nil, errors.New("unsupported") }
func (*ProcessHandle) Alive() error                       { return errors.New("unsupported") }
func (*ProcessHandle) Close() error                       { return nil }
