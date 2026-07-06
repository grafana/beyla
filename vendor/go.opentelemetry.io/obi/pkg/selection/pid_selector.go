// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection // import "go.opentelemetry.io/obi/pkg/selection"

import (
	"context"

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

// PIDSelectorContextNotifier is implemented by selectors that can bind notification channel
// lifetime to a context.
type PIDSelectorContextNotifier interface {
	AddedPIDsNotifyContext(context.Context) <-chan []app.PID
	RemovedNotifyContext(context.Context) <-chan []app.PID
}

// AddedPIDsNotifyContext returns add notifications, using a context-bound subscription when
// the selector supports it.
func AddedPIDsNotifyContext(ctx context.Context, selector PIDSelector) <-chan []app.PID {
	if notifier, ok := selector.(PIDSelectorContextNotifier); ok {
		return notifier.AddedPIDsNotifyContext(ctx)
	}
	return selector.AddedPIDsNotify()
}

// RemovedNotifyContext returns remove notifications, using a context-bound subscription when
// the selector supports it.
func RemovedNotifyContext(ctx context.Context, selector PIDSelector) <-chan []app.PID {
	if notifier, ok := selector.(PIDSelectorContextNotifier); ok {
		return notifier.RemovedNotifyContext(ctx)
	}
	return selector.RemovedNotify()
}

// MutablePIDSelector allows callers to add or remove runtime PIDs for a given signal view.
type MutablePIDSelector interface {
	PIDSelector
	AddPIDs(...uint32)
	AddPID(pid uint32, opts DynamicPIDOptions)
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
	GetPID(pid uint32) (DynamicPIDEntry, bool)
	SetPID(entry DynamicPIDEntry) bool
	// AttrsUpdatedNotify reports PIDs whose shared attributes changed via SetPID or AddPID with options.
	AttrsUpdatedNotify() <-chan app.PID
}
