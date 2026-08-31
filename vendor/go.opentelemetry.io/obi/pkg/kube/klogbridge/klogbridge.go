// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package klogbridge routes k8s.io/klog output through OBI's default slog logger.
//
// Call Install once from each owning application's logger initialization
// (after slog.SetDefault), not from public runtime APIs: klog.SetLoggerWithOptions
// is not thread-safe against concurrent log writes.
package klogbridge // import "go.opentelemetry.io/obi/pkg/kube/klogbridge"

import (
	"bytes"
	"context"
	"flag"
	"io"
	"log/slog"
	"sync"

	"github.com/go-logr/logr"
	"k8s.io/klog/v2"
)

// klogVerbosityWhenDebug is high enough that legacy klog.V(n) calls used by
// client-go are not discarded by klog before they reach this bridge. It is
// only applied while the slog handler enables Debug.
const klogVerbosityWhenDebug = "10"

var (
	klogBridgeOnce sync.Once
	klogFlagSet    *flag.FlagSet
)

// Install routes all k8s.io/klog output (client-go informers, reflectors, etc.)
// through the process-default slog logger, so it honors OBI's log level,
// format, and output stream instead of klog's default raw-stderr format.
//
// Safe to call multiple times; only the first call has an effect. Call after
// slog.SetDefault with the final log level already applied so syncKlogVerbosity
// can see whether Debug is enabled.
func Install() {
	klogBridgeOnce.Do(func() {
		logger := slog.Default().With("component", "k8s.client-go")

		klogFlagSet = flag.NewFlagSet("klogbridge", flag.ContinueOnError)
		klogFlagSet.SetOutput(io.Discard)
		klog.InitFlags(klogFlagSet)
		// Keep klog from also writing the original format to stderr.
		_ = klogFlagSet.Set("logtostderr", "false")
		_ = klogFlagSet.Set("alsologtostderr", "false")
		_ = klogFlagSet.Set("stderrthreshold", "FATAL")
		syncKlogVerbosity()

		klog.SetLoggerWithOptions(
			logr.FromSlogHandler(logger.Handler()),
			klog.ContextualLogger(true),
			klog.WriteKlogBuffer(func(data []byte) {
				level, msg := parseKlogBuffer(data)
				if msg == "" || !logger.Enabled(context.Background(), level) {
					return
				}
				logger.Log(context.Background(), level, msg)
			}),
		)
	})
}

func syncKlogVerbosity() {
	if klogFlagSet == nil {
		return
	}
	v := "0"
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		v = klogVerbosityWhenDebug
	}
	_ = klogFlagSet.Set("v", v)
}

func parseKlogBuffer(data []byte) (slog.Level, string) {
	msg := bytes.TrimSuffix(data, []byte{'\n'})
	if len(msg) == 0 {
		return slog.LevelInfo, ""
	}

	level := slog.LevelInfo
	switch msg[0] {
	case 'I':
		level = slog.LevelInfo
	case 'W':
		level = slog.LevelWarn
	case 'E', 'F':
		level = slog.LevelError
	}

	if i := bytes.Index(msg, []byte("] ")); i >= 0 && i+2 <= len(msg) {
		msg = msg[i+2:]
	}
	return level, string(msg)
}
