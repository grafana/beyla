// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/appolly/meta"

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
)

func linuxLocalFetcher(_ context.Context) (NodeMeta, error) {
	mid, err := fetchMachineID()
	if err != nil {
		// If we can't read host ID, we don't retry as it is mostly
		// (1) this linux distribution does not have the files where we are supposing
		// (2) there is some unrecoverable disk error
		// (3) we lack permissions
		// Then in this case, we only log a debug message
		slog.Debug("can't get local machine ID",
			"component", "meta.linuxLocalFetcher",
			"error", err)
	}
	return NodeMeta{
		HostID: mid,
	}, nil
}

func fetchMachineID() (string, error) {
	if result, err := os.ReadFile("/etc/machine-id"); err == nil && len(bytes.TrimSpace(result)) > 0 {
		return string(bytes.TrimSpace(result)), nil
	}

	if result, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil && len(bytes.TrimSpace(result)) > 0 {
		return string(bytes.TrimSpace(result)), nil
	} else {
		return "", fmt.Errorf("can't read host ID: %w", err)
	}
}
