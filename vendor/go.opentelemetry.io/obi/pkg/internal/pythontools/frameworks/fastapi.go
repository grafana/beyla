// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import "strings"

func ParseFastAPI(args []string) PythonLaunch {
	for i, arg := range args {
		if arg != "run" && arg != "dev" {
			if _, known := fastAPIGlobalOptionsWithoutValues[arg]; known {
				continue
			}
			return PythonLaunch{}
		}
		commandArgs, ok := parseFastAPIArguments(args[i+1:])
		if !ok {
			return PythonLaunch{}
		}
		if commandArgs.explicitEntryPoint {
			entryPoint := commandArgs.entryPoint
			if CleanValue(entryPoint) != entryPoint || commandArgs.appOption || len(commandArgs.positionals) != 0 ||
				!isStrictApplicationReference(entryPoint) {
				return PythonLaunch{}
			}
			return PythonLaunch{Target: entryPoint, TargetKind: TargetModule, SearchPaths: []string{"."}}
		}
		if len(commandArgs.positionals) == 0 {
			if commandArgs.appOption {
				return PythonLaunch{}
			}
			return PythonLaunch{FastAPIAuto: true}
		}
		if len(commandArgs.positionals) != 1 {
			return PythonLaunch{}
		}
		target := commandArgs.positionals[0]
		return PythonLaunch{Target: target, TargetKind: ClassifyTarget(target)}
	}
	return PythonLaunch{}
}

type fastAPIArguments struct {
	positionals        []string
	entryPoint         string
	explicitEntryPoint bool
	appOption          bool
}

func parseFastAPIArguments(args []string) (fastAPIArguments, bool) {
	var parsed fastAPIArguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			parsed.positionals = append(parsed.positionals, args[i+1:]...)
			return parsed, true
		}
		if strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(arg, "=")
			if _, consumes := fastAPIOptionsWithValues[name]; !consumes {
				if _, known := fastAPIOptionsWithoutValues[name]; !known || attached {
					return fastAPIArguments{}, false
				}
				continue
			}
			if !attached {
				if i+1 == len(args) {
					return fastAPIArguments{}, false
				}
				i++
				value = args[i]
			}
			switch name {
			case "--entrypoint":
				parsed.entryPoint = value
				parsed.explicitEntryPoint = true
			case "--app":
				parsed.appOption = true
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			for j := 1; j < len(arg); j++ {
				name := "-" + arg[j:j+1]
				if _, consumes := fastAPIOptionsWithValues[name]; consumes {
					value := arg[j+1:]
					if value == "" {
						if i+1 == len(args) {
							return fastAPIArguments{}, false
						}
						i++
						value = args[i]
					}
					if name == "-e" {
						parsed.entryPoint = value
						parsed.explicitEntryPoint = true
					}
					break
				}
				if _, known := fastAPIOptionsWithoutValues[name]; !known {
					return fastAPIArguments{}, false
				}
			}
			continue
		}
		parsed.positionals = append(parsed.positionals, arg)
	}
	return parsed, true
}

var fastAPIOptionsWithValues = optionSet(
	"--host", "--port", "--uds", "--fd", "--app", "--entrypoint", "-e", "--root-path",
	"--forwarded-allow-ips", "--workers", "--reload-delay", "--reload-dir", "--reload-include", "--reload-exclude",
)

var fastAPIOptionsWithoutValues = optionSet(
	"--reload", "--no-reload", "--proxy-headers", "--no-proxy-headers", "--verbose", "-v", "--help", "-h",
)

var fastAPIGlobalOptionsWithoutValues = optionSet(
	"--verbose", "--no-verbose",
)
