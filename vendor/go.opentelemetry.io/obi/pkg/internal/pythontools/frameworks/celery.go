// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import "strings"

func ParseCelery(args []string, env map[string]string) PythonLaunch {
	target := env["CELERY_APP"]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case (arg == "-A" || arg == "--app") && i+1 < len(args):
			i++
			target = args[i]
		case strings.HasPrefix(arg, "--app="):
			target = strings.TrimPrefix(arg, "--app=")
		case strings.HasPrefix(arg, "-A") && len(arg) > 2:
			target = strings.TrimPrefix(arg[2:], "=")
		}
	}
	return PythonLaunch{Target: target, TargetKind: ClassifyTarget(target)}
}
