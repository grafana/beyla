// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || dragonfly || freebsd || netbsd || openbsd || solaris

package resource // import "github.com/grafana/opentelemetry-go/sdk/resource"

import "os"

func readFile(filename string) (string, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
