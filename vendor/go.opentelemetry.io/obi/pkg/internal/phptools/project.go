// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools // import "go.opentelemetry.io/obi/pkg/internal/phptools"

import (
	"errors"
	"path/filepath"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

func ProjectForPID(fileInfo *exec.FileInfo) (ProjectMetadata, error) {
	if fileInfo == nil {
		return ProjectMetadata{}, errors.New("PHP project discovery requires process file info")
	}

	cwd, cwdErr := cwdForPID(fileInfo.Pid())
	if cwdErr != nil {
		cwd = string(filepath.Separator)
	}

	isFPM := isPHPFPM(fileInfo.ExecutableName())
	var args []string
	var cmdlineErr error
	if !isFPM {
		_, args, cmdlineErr = cmdlineForPID(fileInfo.Pid())
	}

	project := findProject(rootDirForPID(fileInfo.Pid()), cwd, args, isFPM)
	return project, errors.Join(cwdErr, cmdlineErr)
}
