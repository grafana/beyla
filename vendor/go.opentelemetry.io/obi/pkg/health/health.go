// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package health exposes a /healthz endpoint reporting that the OBI process
// is reachable and its scheduler is alive.
package health // import "go.opentelemetry.io/obi/pkg/health"

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/net/netutil"
)

const (
	path          = "/healthz"
	schemaVersion = 1

	maxOpenConns      = 100
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 5 * time.Second
	writeTimeout      = 5 * time.Second
	idleTimeout       = 5 * time.Second
)

// DefaultListenAddress keeps the TCP health endpoint local unless configured otherwise.
const DefaultListenAddress = "127.0.0.1"

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

func tcpListenAddr(address string, port int) string {
	if address == "" {
		address = DefaultListenAddress
	}

	return net.JoinHostPort(address, strconv.Itoa(port))
}

func ListenAndServe(ctx context.Context, port int) error {
	return ListenAndServeTCP(ctx, DefaultListenAddress, port)
}

func ListenAndServeTCP(ctx context.Context, address string, port int) error {
	listenAddr := tcpListenAddr(address, port)
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log().With("address", listenAddr).Error("can't bind health endpoint", "err", err)
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

func newServer() *http.Server {
	mux := http.NewServeMux()
	mux.Handle(path, &endpoint{start: time.Now()})

	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

func Serve(ctx context.Context, lis net.Listener) error {
	server := newServer()
	lis = netutil.LimitListener(lis, maxOpenConns)

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
