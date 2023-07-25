// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !nopc

package slog

import (
	"context"
	"runtime"
	"time"
)

// These functions compute the pc early and pass it down the call chain,
// which is faster than computing it later with a larger skip.

// LogDepth is like [Logger.Log], but accepts a call depth to adjust the
// file and line number in the log record. 1 refers to the caller
// of LogDepth; 2 refers to the caller's caller; and so on.
func (l *Logger) logDepth(ctx context.Context, calldepth int, level Level, msg string, args ...any) {
	if !l.Enabled(ctx, level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(calldepth+2, pcs[:])
	l.logPC(ctx, nil, pcs[0], level, msg, args...)
}

// LogAttrsDepth is like [Logger.LogAttrs], but accepts a call depth argument
// which it interprets like [Logger.LogDepth].
func (l *Logger) logAttrsDepth(ctx context.Context, calldepth int, level Level, msg string, attrs ...Attr) {
	if !l.Enabled(ctx, level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(calldepth+2, pcs[:])
	r := NewRecord(time.Now(), level, msg, pcs[0])
	r.AddAttrs(attrs...)
	_ = l.Handler().Handle(ctx, r)
}

// logDepthErr is a trivial wrapper around logDepth, just to make the call
// depths on all paths the same. This is important only for the defaultHandler,
// which passes a fixed call depth to log.Output.
// TODO: When slog moves to the standard library, replace the fixed call depth
// with logic based on the Record's pc, and remove this function. See the
// comment on TestConnections/wrap_default_handler.
func (l *Logger) logDepthErr(ctx context.Context, err error, calldepth int, level Level, msg string, args ...any) {
	if !l.Enabled(ctx, level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(calldepth+2, pcs[:])
	l.logPC(ctx, err, pcs[0], level, msg, args...)
}

// callerPC returns the program counter at the given stack depth.
func callerPC(depth int) uintptr {
	var pcs [1]uintptr
	runtime.Callers(depth, pcs[:])
	return pcs[0]
}
