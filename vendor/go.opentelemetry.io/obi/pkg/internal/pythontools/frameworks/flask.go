// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import (
	"strings"
)

func ParseFlask(args []string, env map[string]string) PythonLaunch {
	target := env["FLASK_APP"]

options:
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--":
			break options
		case (args[i] == "-A" || args[i] == "--app") && i+1 < len(args):
			i++
			target = args[i]
		case strings.HasPrefix(args[i], "-A") && len(args[i]) > 2:
			target = strings.TrimPrefix(strings.TrimPrefix(args[i], "-A"), "=")
		case strings.HasPrefix(args[i], "--app="):
			target = strings.TrimPrefix(args[i], "--app=")
		}
	}

	launch := PythonLaunch{Target: target, TargetKind: ClassifyTarget(target)}
	if target == "" {
		launch.FlaskAuto = true
		return launch
	}
	if launch.TargetKind == TargetModule {
		launch.SearchPaths = []string{"."}
	}
	return launch
}
