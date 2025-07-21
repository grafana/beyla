// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kubeflags

type EnableFlag string

const (
	EnabledTrue       = EnableFlag("true")
	EnabledFalse      = EnableFlag("false")
	EnabledAutodetect = EnableFlag("autodetect")
	EnabledDefault    = EnabledAutodetect
)
