// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package buildinfo // import "go.opentelemetry.io/obi/pkg/buildinfo"

// Version and Revision variables are overridden at build time with Git repository information
// They can be also overridden at runtime by any software component vendoring OBI as library
var (
	Version  = "unset"
	Revision = "unset"
)
