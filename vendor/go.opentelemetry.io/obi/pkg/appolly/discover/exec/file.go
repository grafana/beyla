// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package exec provides the utilities to analyze the executable code
package exec

import (
	"debug/elf"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

type FileInfo struct {
	Service svc.Attrs

	CmdExePath     string
	ProExeLinkPath string
	ELF            *elf.File
	Pid            int32
	Ppid           int32
	Ino            uint64
	Ns             uint32
}

func (fi *FileInfo) ExecutableName() string {
	parts := strings.Split(fi.CmdExePath, "/")
	return parts[len(parts)-1]
}
