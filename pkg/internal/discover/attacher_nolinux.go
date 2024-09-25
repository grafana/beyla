//go:build !linux

package discover

import "log/slog"

func (ta *TraceAttacher) init() error {
	return nil
}

func (ta *TraceAttacher) close() {}

func UnmountBPFFS(_ string, _ *slog.Logger) {}
