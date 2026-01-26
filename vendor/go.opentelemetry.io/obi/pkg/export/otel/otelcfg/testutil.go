// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

import "os"

// RestoreEnvAfterExecution stores the values of some modified env vars to avoid
// interferences between cases. Must be invoked as:
// defer RestoreEnvAfterExecution()()
func RestoreEnvAfterExecution() func() {
	vals := []*struct {
		name   string
		val    string
		exists bool
	}{
		{name: envTracesProtocol},
		{name: envMetricsProtocol},
		{name: envProtocol},
		{name: envHeaders},
		{name: envTracesHeaders},
	}
	for _, v := range vals {
		v.val, v.exists = os.LookupEnv(v.name)
	}
	return func() {
		for _, v := range vals {
			if v.exists {
				os.Setenv(v.name, v.val)
			} else {
				os.Unsetenv(v.name)
			}
		}
	}
}
