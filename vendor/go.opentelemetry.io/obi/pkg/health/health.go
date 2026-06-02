// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package health exposes a /healthz endpoint reporting that the OBI process
// is reachable and its scheduler is alive.
package health // import "go.opentelemetry.io/obi/pkg/health"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

const (
	path          = "/healthz"
	schemaVersion = 1
)

func log() *slog.Logger {
	return slog.With("component", "health")
}

type endpoint struct {
	start time.Time
}

func (e *endpoint) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	resp := struct {
		SchemaVersion   int   `json:"schema_version"`
		NowUnixNs       int64 `json:"now_unix_ns"`
		ProcessUptimeNs int64 `json:"process_uptime_ns"`
	}{
		SchemaVersion:   schemaVersion,
		NowUnixNs:       now.UnixNano(),
		ProcessUptimeNs: now.Sub(e.start).Nanoseconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&resp)
}

func ListenAndServe(ctx context.Context, port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log().With("port", port).Error("can't bind health endpoint", "err", err)
		return nil
	}

	return Serve(ctx, lis)
}

func ListenAndServeUDS(ctx context.Context, addr string) error {
	lis, err := net.Listen("unix", addr)
	if err != nil {
		log().With("addr", addr).Error("can't bind health endpoint", "err", err)
		return nil
	}

	return Serve(ctx, lis)
}

func Serve(ctx context.Context, lis net.Listener) error {
	mux := http.NewServeMux()
	mux.Handle(path, &endpoint{start: time.Now()})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	l := log().With("addr", lis.Addr().String(), "path", path)
	l.Info("starting health endpoint")

	srvErr := make(chan error, 1)
	go func() {
		err := server.Serve(lis)
		if !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			l.Warn("error closing health endpoint", "err", err)
		}
		return nil

	case err := <-srvErr:
		if err != nil {
			l.Error("health endpoint exited unexpectedly", "err", err)
		}
		return nil
	}
}
