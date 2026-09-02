// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnettools // import "go.opentelemetry.io/obi/pkg/internal/dotnettools"

import (
	"path/filepath"
	"strings"
)

type dotnetLaunch struct {
	EntryPoint string
	DepsFile   string
}

var dotnetOptionsWithValues = map[string]struct{}{
	"--additional-deps":                 {},
	"--additionalprobingpath":           {},
	"--depsfile":                        {},
	"--fx-version":                      {},
	"--property":                        {},
	"--roll-forward":                    {},
	"--roll-forward-on-no-candidate-fx": {},
	"--runtimeconfig":                   {},
}

func parseDotnetLaunch(args []string) dotnetLaunch {
	var launch dotnetLaunch
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue
		}
		if i == 0 && arg == "exec" {
			continue
		}
		if arg == "--" {
			if i+1 < len(args) && isDLL(args[i+1]) {
				launch.EntryPoint = args[i+1]
			}
			return launch
		}
		if value, ok := strings.CutPrefix(arg, "--depsfile="); ok {
			launch.DepsFile = value
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if _, ok := dotnetOptionsWithValues[arg]; ok && i+1 < len(args) {
				if arg == "--depsfile" {
					launch.DepsFile = args[i+1]
				}
				i++
			}
			continue
		}
		if isDLL(arg) {
			launch.EntryPoint = arg
		}
		return launch
	}

	return launch
}

func isDLL(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".dll")
}
