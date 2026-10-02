// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracefs // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type ProbeType string

const (
	Uprobe ProbeType = "uprobe"
	Kprobe ProbeType = "kprobe"

	shutdownTimeoutMultiplier = 3
)

type Options struct {
	Type ProbeType
	// Targets are kernel symbols or executable:offset[(ref_ctr_offset)] targets.
	Targets []string
	PID     uint32
	Return  bool
}

var fallbackUsed atomic.Bool

var fallbackLogs = map[ProbeType]*struct{ success, failure sync.Once }{
	Uprobe: {},
	Kprobe: {},
}

// EffectiveShutdownTimeout allows for per-event RCU waits on older kernels
// which cannot remove tracefs probes as a group.
func EffectiveShutdownTimeout(configured time.Duration) time.Duration {
	if fallbackUsed.Load() {
		return shutdownTimeoutMultiplier * configured
	}
	return configured
}

func WithFallback(kind ProbeType, attachPerf, attachTraceFS func() (io.Closer, error)) (io.Closer, error) {
	closer, err := attachPerf()
	if err == nil || !errors.Is(err, unix.EACCES) {
		return closer, err
	}

	slog.Debug("PMU access denied, trying tracefs", "probe_type", kind, "error", err)
	closer, traceErr := attachTraceFS()
	if traceErr != nil {
		fallbackLogs[kind].failure.Do(func() {
			slog.Error("tracefs fallback failed; ensure tracefs is writable (CAP_DAC_OVERRIDE may be required)",
				"probe_type", kind, "error", traceErr)
		})
		return nil, errors.Join(err, traceErr)
	}

	fallbackUsed.Store(true)
	fallbackLogs[kind].success.Do(func() {
		slog.Info(fmt.Sprintf("attached %s through tracefs because PMU access was denied", kind), "pmu_error", err)
	})
	return closer, nil
}
