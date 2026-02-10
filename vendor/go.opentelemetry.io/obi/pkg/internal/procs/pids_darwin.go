// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"
import "go.opentelemetry.io/obi/pkg/appolly/app"

func FindNamespace(_ app.PID) (uint32, error) {
	// convenience method to allow unit tests compiling in Darwin
	return 0, nil
}

func FindNamespacedPids(_ app.PID) ([]app.PID, error) {
	return nil, nil
}
