// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection // import "go.opentelemetry.io/obi/pkg/selection"

import "go.opentelemetry.io/obi/pkg/appolly/app"

// DynamicPIDOptions holds optional service identity and resource attributes when adding
// a PID to a signal view. Attributes are shared across all signals for the same PID.
type DynamicPIDOptions struct {
	ServiceName        string
	ServiceNamespace   string
	ResourceAttributes map[string]string
}

// DynamicPIDEntry describes a tracked PID and its shared attributes. Use GetPID to read and
// SetPID to update attributes for a PID that is already in the selector.
type DynamicPIDEntry struct {
	PID                app.PID
	ServiceName        string
	ServiceNamespace   string
	ResourceAttributes map[string]string
}
