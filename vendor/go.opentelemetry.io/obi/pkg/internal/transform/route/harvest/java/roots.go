// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/java"

import (
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools"
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

func (e *Extractor) findScanRoots(fileInfo *exec.FileInfo) ([]jvmtools.ScanRoot, error) {
	pid := fileInfo.Pid()
	_, args, err := cmdlineForPID(pid)
	if err != nil {
		return nil, fmt.Errorf("error finding Java cmd line: %w", err)
	}
	cwd, err := cwdForPID(pid)
	if err != nil {
		return nil, fmt.Errorf("error finding Java cwd: %w", err)
	}

	return jvmtools.ScanRoots(rootDirForPID(pid), cwd, args, fileInfo.ServiceAttrs().EnvVars)
}
