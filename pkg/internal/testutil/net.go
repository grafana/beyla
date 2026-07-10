// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package testutil // import "go.opentelemetry.io/obi/pkg/internal/testutil"

import (
	"net"
	"testing"
	"time"
)

const tcpPortTimeout = 5 * time.Second

// FreeTCPPort returns a free TCP port that can be used for testing.
func FreeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", ":")
	if err != nil {
		t.Fatalf("failed to find a free TCP port: %v", err)
	}

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("failed to get TCP address")
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	// wait until the listener port is effectively closed
	deadline := time.Now().Add(tcpPortTimeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr.String(), 10*time.Millisecond)
		if err != nil {
			return addr.Port
		}
		conn.Close()
	}
	t.Fatalf("port %d was not released within %s", addr.Port, tcpPortTimeout)
	return 0
}
