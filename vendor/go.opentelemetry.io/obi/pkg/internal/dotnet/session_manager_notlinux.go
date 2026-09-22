// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type SessionManager struct{}

func NewSessionManager(context.Context, time.Duration, time.Duration, *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot]) *SessionManager {
	return &SessionManager{}
}

func (*SessionManager) Start(*exec.FileInfo) error {
	return errors.New(".NET runtime metrics are only supported on Linux")
}

func (*SessionManager) Remove(*exec.FileInfo) {}
func (*SessionManager) Close()                {}
