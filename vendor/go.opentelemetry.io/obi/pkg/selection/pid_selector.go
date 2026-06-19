// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection // import "go.opentelemetry.io/obi/pkg/selection"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// PIDSelector is the read-only contract for runtime dynamic PID membership in one signal view.
// Implementations notify subscribers when PIDs enter or leave the view.
type PIDSelector interface {
	GetPIDs() ([]app.PID, bool)
	IncludesPID(app.PID) bool
	AddedPIDsNotify() <-chan []app.PID
	RemovedNotify() <-chan []app.PID
}

// MutablePIDSelector allows callers to add or remove runtime PIDs for a given signal view.
type MutablePIDSelector interface {
	PIDSelector
	AddPIDs(...uint32)
	RemovePIDs(...uint32)
}

// MultiSignalPIDSelector exposes one root selector with subviews for each supported signal.
// *discover.DynamicPIDSelector implements this interface.
type MultiSignalPIDSelector interface {
	MutablePIDSelector
	Traces() MutablePIDSelector
	AppMetrics() MutablePIDSelector
	NetworkMetrics() MutablePIDSelector
	StatsMetrics() MutablePIDSelector
}
