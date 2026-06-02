// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const unixSchemePrefix = "unix://"

// sockaddr_un.sun_path is 108 bytes.
// pathname sockets need a trailing NUL;
// abstract names do not.
const unixPathMax = 108

func unixSocketEndpoint(endpoint string) (string, bool) {
	if !strings.HasPrefix(endpoint, unixSchemePrefix) {
		return "", false
	}

	return strings.TrimPrefix(endpoint, unixSchemePrefix), true
}

func validateUnixSocketAddr(addr string) error {
	switch {
	case addr == "":
		return errors.New("unix socket address is empty")
	case strings.HasPrefix(addr, "@"):
		if len(addr) > unixPathMax {
			return fmt.Errorf("abstract unix socket name %q exceeds the %d-byte limit", addr, unixPathMax)
		}
	case strings.HasPrefix(addr, "/"):
		if len(addr) > unixPathMax-1 {
			return fmt.Errorf("unix socket path %q exceeds the %d-byte limit", addr, unixPathMax-1)
		}
	default:
		return fmt.Errorf("unix socket address %q must be an absolute path or an abstract name (leading '@')", addr)
	}

	return nil
}

func UnixTransport(addr string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		},
	}
}

func unixHTTPClient(addr string) *http.Client {
	return &http.Client{Transport: UnixTransport(addr)}
}

func grpcUnixTarget(addr string) string {
	if name, ok := strings.CutPrefix(addr, "@"); ok {
		return "unix-abstract:" + name
	}

	return "unix://" + addr
}
