// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime // import "go.opentelemetry.io/obi/pkg/appolly/app/runtime"

import (
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

type PythonGCGenerationMetrics struct {
	Collections          uint64
	CollectedObjects     uint64
	UncollectableObjects uint64
}

// PythonRuntimeMetricFinal carries one PID's last cumulative GC snapshot.
// The process-event path emits the remaining counter delta before the PID tombstone.
type PythonRuntimeMetricFinal struct {
	PID         app.PID
	Generation  uint64
	Time        time.Time
	HasValue    bool
	Generations [3]PythonGCGenerationMetrics
}
