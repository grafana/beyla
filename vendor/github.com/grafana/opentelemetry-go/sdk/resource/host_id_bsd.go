// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build dragonfly || freebsd || netbsd || openbsd || solaris
// +build dragonfly freebsd netbsd openbsd solaris

package resource // import "github.com/grafana/opentelemetry-go/sdk/resource"

var platformHostIDReader hostIDReader = &hostIDReaderBSD{
	execCommand: execCommand,
	readFile:    readFile,
}
