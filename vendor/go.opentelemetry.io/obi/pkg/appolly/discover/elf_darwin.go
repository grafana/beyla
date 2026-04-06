// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

// dummy implementations to avoid compilation errors in Darwin.

func FindINodeForPID(_ app.PID) (dev uint64, ino uint64, err error) {
	return 0, 0, errors.New("FindINodeForPID is not supported on this platform")
}

func findExecElf(_ *services.ProcessInfo, _ svc.Attrs) (*exec.FileInfo, error) {
	return nil, errors.New("findExecElf is not supported on this platform")
}
