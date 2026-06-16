// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package util // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/util"

import "errors"

const MaxPath = 4096

var errUnsupported = errors.New("jvmtools process helpers are only supported on linux")

func GetTmpPath(_ int) string {
	return ""
}

func GetProcessInfo(_ int, _ *int, _ *int, _ *int) error {
	return errUnsupported
}

func EnterNS(_ int, _ string) int {
	return -1
}
