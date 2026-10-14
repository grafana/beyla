// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
)

// javaInjectionQueueLen bounds how many discovered JVMs can wait for injection.
// The queue only fills while an attach is stuck, and a dropped target loses Java
// TLS telemetry for that process, nothing else.
const javaInjectionQueueLen = 100

func newJavaInjectionQueue(
	log *slog.Logger,
	slot injectionSlot,
	inject func(context.Context, javaagent.InjectionTarget) error,
) *injectionQueue[javaagent.InjectionTarget] {
	return newInjectionQueue(log, "java", slot, javaInjectionQueueLen,
		func(ctx context.Context, target javaagent.InjectionTarget) {
			if err := inject(ctx, target); err != nil {
				log.Warn("unable to attach java agent to process, Java TLS telemetry will not work",
					"pid", target.Pid, "error", err)
			}
		},
		func(target javaagent.InjectionTarget) bool {
			return target.Type == svc.InstrumentableJava
		})
}
