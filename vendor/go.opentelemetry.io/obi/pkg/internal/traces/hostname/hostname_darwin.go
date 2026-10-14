// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build darwin

package hostname // import "go.opentelemetry.io/obi/pkg/internal/traces/hostname"

import "os"

// dummy methods to allow compilation
func internalHostname() (hn string, err error) {
	return os.Hostname()
}

func getFqdnHostname(_ string) (string, error) {
	return os.Hostname()
}
