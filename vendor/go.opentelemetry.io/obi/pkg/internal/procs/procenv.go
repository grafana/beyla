// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"strings"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func envStrsToMap(varsStr []string) map[string]string {
	vars := make(map[string]string, validEnvCount(varsStr))

	for _, s := range varsStr {
		if key, val, ok := parseEnvVar(s); ok {
			vars[key] = val
		}
	}

	return vars
}

func validEnvCount(varsStr []string) int {
	count := 0
	for _, s := range varsStr {
		if _, _, ok := parseEnvVar(s); ok {
			count++
		}
	}
	return count
}

func parseEnvVar(s string) (string, string, bool) {
	key, val, found := strings.Cut(s, "=")
	if !found {
		return "", "", false
	}

	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)
	return key, val, key != "" && val != ""
}

func EnvVars(pid app.PID) (map[string]string, error) {
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return nil, err
	}

	varsStr, err := proc.Environ()
	if err != nil {
		return nil, err
	}

	m := envStrsToMap(varsStr)

	return m, nil
}
