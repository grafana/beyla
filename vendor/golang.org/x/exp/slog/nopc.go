// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Use the nopc flag for benchmarks, on the assumption
// that retrieving the pc will become cheap.

//go:build nopc

package slog

import "time"

// LogDepth is like [Logger.Log], but accepts a call depth to adjust the
// file and line number in the log record. 0 refers to the caller
// of LogDepth; 1 refers to the caller's caller; and so on.
func (l *Logger) LogDepth(calldepth int, level Level, msg string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	l.logPC(nil, 0, level, msg, args...)
}

// LogAttrsDepth is like [Logger.LogAttrs], but accepts a call depth argument
// which it interprets like [Logger.LogDepth].
func (l *Logger) LogAttrsDepth(calldepth int, level Level, msg string, attrs ...Attr) {
	if !l.Enabled(level) {
		return
	}
	r := NewRecord(time.Now(), level, msg, 0, l.ctx)
	r.AddAttrs(attrs...)
	_ = l.Handler().Handle(r)
}

// logDepthErr is a trivial wrapper around logDepth, just to make the call
// depths on all paths the same. This is important only for the defaultHandler,
// which passes a fixed call depth to log.Output. When slog moves to the
// standard library, we can replace that fixed call depth with logic based on
// the Record's pc, and remove this function. See the comment on
// TestConnections/wrap_default_handler.
func (l *Logger) logDepthErr(err error, calldepth int, level Level, msg string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	l.logPC(err, 0, level, msg, args...)
}

// callerPC returns 0 to avoid incurring the cost of runtime.Callers.
func callerPC(depth int) uintptr { return 0 }
