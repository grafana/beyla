// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

func ParseDjango(args []string, env map[string]string) PythonLaunch {
	target := lastLongOptionValue(args, "--settings", env["DJANGO_SETTINGS_MODULE"])
	launch := PythonLaunch{Target: target, TargetKind: ClassifyTarget(target)}
	if pythonPath := lastLongOptionValue(args, "--pythonpath", ""); pythonPath != "" {
		launch.SearchPaths = []string{pythonPath}
	}
	return launch
}
