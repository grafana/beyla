// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import (
	"slices"
	"strings"
)

type uwsgiSettings struct {
	module      string
	file        string
	pythonPaths []string
}

func ParseUWSGI(args []string) PythonLaunch {
	var settings uwsgiSettings

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, attached := strings.Cut(arg, "=")
		if strings.HasPrefix(arg, "-w") && !strings.HasPrefix(arg, "--") && len(arg) > 2 {
			name = "-w"
			value = strings.TrimPrefix(strings.TrimPrefix(arg, "-w"), "=")
			attached = true
		}
		switch name {
		case "-w", "--module", "--wsgi":
			if !attached {
				if i+1 == len(args) {
					return PythonLaunch{}
				}
				i++
				value = args[i]
			}
			settings.module = value
		case "--wsgi-file", "--file":
			if !attached {
				if i+1 == len(args) {
					return PythonLaunch{}
				}
				i++
				value = args[i]
			}
			settings.file = value
		case "--pythonpath", "--python-path", "--pp":
			if !attached {
				if i+1 == len(args) {
					return PythonLaunch{}
				}
				i++
				value = args[i]
			}
			settings.pythonPaths = append(settings.pythonPaths, value)
		}
	}

	launch := PythonLaunch{}

	if settings.module != "" && settings.file != "" {
		return launch
	}

	if settings.module != "" {
		launch.Target = settings.module
		launch.TargetKind = TargetModule
	} else if settings.file != "" {
		launch.Target = settings.file
		launch.TargetKind = TargetFile
	}

	for _, v := range slices.Backward(settings.pythonPaths) {
		launch.SearchPaths = append(launch.SearchPaths, v)
	}

	launch.SearchPaths = append(launch.SearchPaths, ".")

	return launch
}
