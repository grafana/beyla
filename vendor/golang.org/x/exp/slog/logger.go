// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package slog

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

var defaultLogger atomic.Value

func init() {
	defaultLogger.Store(New(newDefaultHandler(log.Output)))
}

// Default returns the default Logger.
func Default() *Logger { return defaultLogger.Load().(*Logger) }

// SetDefault makes l the default Logger.
// After this call, output from the log package's default Logger
// (as with [log.Print], etc.) will be logged at LevelInfo using l's Handler.
func SetDefault(l *Logger) {
	defaultLogger.Store(l)
	// If the default's handler is a defaultHandler, then don't use a handleWriter,
	// or we'll deadlock as they both try to acquire the log default mutex.
	// The defaultHandler will use whatever the log default writer is currently
	// set to, which is correct.
	// This can occur with SetDefault(Default()).
	// See TestSetDefault.
	if _, ok := l.Handler().(*defaultHandler); !ok {
		capturePC := log.Flags()&(log.Lshortfile|log.Llongfile) != 0
		log.SetOutput(&handlerWriter{l.Handler(), LevelInfo, capturePC})
		log.SetFlags(0) // we want just the log message, no time or location
	}
}

// handlerWriter is an io.Writer that calls a Handler.
// It is used to link the default log.Logger to the default slog.Logger.
type handlerWriter struct {
	h         Handler
	level     Level
	capturePC bool
}

func (w *handlerWriter) Write(buf []byte) (int, error) {
	if !w.h.Enabled(nil, w.level) {
		return 0, nil
	}
	var pc uintptr
	if w.capturePC {
		// skip [runtime.Callers, callerPC, w.Write, Logger.Output, log.Print]
		pc = callerPC(5)
	}

	// Remove final newline.
	origLen := len(buf) // Report that the entire buf was written.
	if len(buf) > 0 && buf[len(buf)-1] == '\n' {
		buf = buf[:len(buf)-1]
	}
	r := NewRecord(time.Now(), w.level, string(buf), pc)
	return origLen, w.h.Handle(nil, r)
}

// A Logger records structured information about each call to its
// Log, Debug, Info, Warn, and Error methods.
// For each call, it creates a Record and passes it to a Handler.
//
// To create a new Logger, call [New] or a Logger method
// that begins "With".
type Logger struct {
	handler Handler // for structured logging
}

func (l *Logger) clone() *Logger {
	c := *l
	return &c
}

// Handler returns l's Handler.
func (l *Logger) Handler() Handler { return l.handler }

// With returns a new Logger that includes the given arguments, converted to
// Attrs as in [Logger.Log] and resolved.
// The Attrs will be added to each output from the Logger.
// The new Logger shares the old Logger's context.
// The new Logger's handler is the result of calling WithAttrs on the receiver's
// handler.
func (l *Logger) With(args ...any) *Logger {
	var (
		attr  Attr
		attrs []Attr
	)
	for len(args) > 0 {
		attr, args = argsToAttr(args)
		attrs = append(attrs, attr)
	}
	c := l.clone()
	c.handler = l.handler.WithAttrs(attrs)
	return c
}

// WithGroup returns a new Logger that starts a group. The keys of all
// attributes added to the Logger will be qualified by the given name.
// The new Logger shares the old Logger's context.
//
// The new Logger's handler is the result of calling WithGroup on the receiver's
// handler.
func (l *Logger) WithGroup(name string) *Logger {
	c := l.clone()
	c.handler = l.handler.WithGroup(name)
	return c

}

// New creates a new Logger with the given non-nil Handler and a nil context.
func New(h Handler) *Logger {
	if h == nil {
		panic("nil Handler")
	}
	return &Logger{handler: h}
}

// With calls Logger.With on the default logger.
func With(args ...any) *Logger {
	return Default().With(args...)
}

// Enabled reports whether l emits log records at the given context and level.
func (l *Logger) Enabled(ctx context.Context, level Level) bool {
	return l.Handler().Enabled(ctx, level)
}

// NewLogLogger returns a new log.Logger such that each call to its Output method
// dispatches a Record to the specified handler. The logger acts as a bridge from
// the older log API to newer structured logging handlers.
func NewLogLogger(h Handler, level Level) *log.Logger {
	return log.New(&handlerWriter{h, level, true}, "", 0)
}

// Log emits a log record with the current time and the given level and message.
// The Record's Attrs consist of the Logger's attributes followed by
// the Attrs specified by args.
//
// The attribute arguments are processed as follows:
//   - If an argument is an Attr, it is used as is.
//   - If an argument is a string and this is not the last argument,
//     the following argument is treated as the value and the two are combined
//     into an Attr.
//   - Otherwise, the argument is treated as a value with key "!BADKEY".
func (l *Logger) Log(ctx context.Context, level Level, msg string, args ...any) {
	l.logDepth(ctx, 1, level, msg, args...)
}

func (l *Logger) logPC(ctx context.Context, err error, pc uintptr, level Level, msg string, args ...any) {
	r := NewRecord(time.Now(), level, msg, pc)
	if err != nil {
		r.front[0] = Any(ErrorKey, err)
		r.nFront++
	}
	r.Add(args...)
	_ = l.Handler().Handle(ctx, r)
}

// LogAttrs is a more efficient version of [Logger.Log] that accepts only Attrs.
func (l *Logger) LogAttrs(ctx context.Context, level Level, msg string, attrs ...Attr) {
	l.logAttrsDepth(ctx, 1, level, msg, attrs...)
}

// Debug logs at LevelDebug.
func (l *Logger) Debug(msg string, args ...any) {
	l.logDepth(nil, 1, LevelDebug, msg, args...)
}

// DebugCtx logs at LevelDebug with the given context.
func (l *Logger) DebugCtx(ctx context.Context, msg string, args ...any) {
	l.logDepth(ctx, 1, LevelDebug, msg, args...)
}

// Info logs at LevelInfo.
func (l *Logger) Info(msg string, args ...any) {
	l.logDepth(nil, 1, LevelInfo, msg, args...)
}

// InfoCtx logs at LevelInfo with the given context.
func (l *Logger) InfoCtx(ctx context.Context, msg string, args ...any) {
	l.logDepth(ctx, 1, LevelInfo, msg, args...)
}

// Warn logs at LevelWarn.
func (l *Logger) Warn(msg string, args ...any) {
	l.logDepth(nil, 1, LevelWarn, msg, args...)
}

// WarnCtx logs at LevelWarn with the given context.
func (l *Logger) WarnCtx(ctx context.Context, msg string, args ...any) {
	l.logDepth(ctx, 1, LevelWarn, msg, args...)
}

// Error logs at LevelError.
// If err is non-nil, Error adds Any(ErrorKey, err)
// before the list of attributes.
func (l *Logger) Error(msg string, err error, args ...any) {
	l.logDepthErr(nil, err, 1, LevelError, msg, args...)
}

// ErrorCtx logs at LevelError with the given context.
// If err is non-nil, it adds Any(ErrorKey, err)
// before the list of attributes.
func (l *Logger) ErrorCtx(ctx context.Context, msg string, err error, args ...any) {
	l.logDepthErr(ctx, err, 1, LevelError, msg, args...)
}

// Debug calls Logger.Debug on the default logger.
func Debug(msg string, args ...any) {
	Default().logDepth(nil, 1, LevelDebug, msg, args...)
}

// DebugCtx calls Logger.DebugCtx on the default logger.
func DebugCtx(ctx context.Context, msg string, args ...any) {
	Default().logDepth(ctx, 1, LevelDebug, msg, args...)
}

// Info calls Logger.Info on the default logger.
func Info(msg string, args ...any) {
	Default().logDepth(nil, 1, LevelInfo, msg, args...)
}

// InfoCtx calls Logger.InfoCtx on the default logger.
func InfoCtx(ctx context.Context, msg string, args ...any) {
	Default().logDepth(ctx, 1, LevelInfo, msg, args...)
}

// Warn calls Logger.Warn on the default logger.
func Warn(msg string, args ...any) {
	Default().logDepth(nil, 1, LevelWarn, msg, args...)
}

// WarnCtx calls Logger.WarnCtx on the default logger.
func WarnCtx(ctx context.Context, msg string, args ...any) {
	Default().logDepth(ctx, 1, LevelWarn, msg, args...)
}

// Error calls Logger.Error on the default logger.
func Error(msg string, err error, args ...any) {
	Default().logDepthErr(nil, err, 1, LevelError, msg, args...)
}

// ErrorCtx calls Logger.ErrorCtx on the default logger.
func ErrorCtx(ctx context.Context, msg string, err error, args ...any) {
	Default().logDepthErr(ctx, err, 1, LevelError, msg, args...)
}

// Log calls Logger.Log on the default logger.
func Log(ctx context.Context, level Level, msg string, args ...any) {
	Default().logDepth(ctx, 1, level, msg, args...)
}

// LogAttrs calls Logger.LogAttrs on the default logger.
func LogAttrs(ctx context.Context, level Level, msg string, attrs ...Attr) {
	Default().logAttrsDepth(ctx, 1, level, msg, attrs...)
}
