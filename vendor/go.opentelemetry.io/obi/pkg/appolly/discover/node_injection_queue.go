// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/internal/nodejs"
)

// nodeInjectionQueueLen bounds how many discovered Node.js processes can wait
// for injection. A dropped target loses trace-context propagation and runtime
// metrics for that process, nothing else.
const nodeInjectionQueueLen = 100

// Admission is decided before the target is built, by NodeInjector.Accepts, so
// the queue needs no predicate of its own.
func newNodeInjectionQueue(
	log *slog.Logger,
	slot injectionSlot,
	inject func(context.Context, nodejs.InjectionTarget),
) *injectionQueue[nodejs.InjectionTarget] {
	return newInjectionQueue(log, "node", slot, nodeInjectionQueueLen, inject, nil)
}
