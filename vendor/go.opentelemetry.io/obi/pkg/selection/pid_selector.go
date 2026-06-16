// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection // import "go.opentelemetry.io/obi/pkg/selection"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// PIDSelector is the read-only contract for runtime dynamic PID membership.
// Implementations notify subscribers when PIDs enter or leave the selected set.
type PIDSelector interface {
	GetPIDs() ([]app.PID, bool)
	AddedPIDsNotify() <-chan []app.PID
	RemovedNotify() <-chan []app.PID
}
