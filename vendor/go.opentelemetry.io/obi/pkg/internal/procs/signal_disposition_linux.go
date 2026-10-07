// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"io"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// SignalDisposition reports what signal would do to the process. The masks are
// read through the handle's pinned process directory, so a recycled PID cannot
// be measured in place of the target.
func (p *ProcessHandle) SignalDisposition(signal unix.Signal) SignalDisposition {
	status, err := p.readStatus()
	if err != nil {
		return SignalDispositionUnknown
	}

	return dispositionFromStatus(status, signal)
}

func (p *ProcessHandle) readStatus() ([]byte, error) {
	f, err := p.Open("status", unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

// maxSignalNum is the highest signal the status file's masks describe.
const maxSignalNum = 64

func dispositionFromStatus(status []byte, signal unix.Signal) SignalDisposition {
	if signal < 1 || signal > maxSignalNum {
		return SignalDispositionUnknown
	}

	mask := uint64(1) << (uint(signal) - 1)

	caught, gotCaught := signalMask(status, "SigCgt:")
	ignored, gotIgnored := signalMask(status, "SigIgn:")
	if !gotCaught || !gotIgnored {
		return SignalDispositionUnknown
	}

	if (caught|ignored)&mask != 0 {
		return SignalDispositionHandled
	}

	return SignalDispositionFatal
}

func signalMask(status []byte, field string) (uint64, bool) {
	for line := range strings.SplitSeq(string(status), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), field)
		if !ok {
			continue
		}

		mask, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return 0, false
		}

		return mask, true
	}

	return 0, false
}
