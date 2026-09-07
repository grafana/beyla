// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

type PythonPathConfig struct {
	IgnorePythonEnvironment bool
	SafePath                bool
}

func (config PythonPathConfig) Apply(launch PythonLaunch) PythonLaunch {
	if launch.TargetKind == TargetNone && launch.Target == "" && launch.FallbackName == "" &&
		!launch.FastAPIAuto && !launch.FlaskAuto && len(launch.SearchPaths) == 0 {
		return launch
	}
	launch.PathConfig = config
	return launch
}
