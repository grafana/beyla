// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import "strings"

func argparseShortOption(
	arg string,
	optionsWithValues map[string]struct{},
	optionsWithoutValues map[string]struct{},
) (bool, bool) {
	for i := 1; i < len(arg); i++ {
		name := "-" + arg[i:i+1]
		if _, known := optionsWithoutValues[name]; known {
			continue
		}
		if _, consumes := optionsWithValues[name]; consumes {
			return i == len(arg)-1, true
		}
		return false, false
	}
	return false, true
}

func argparsePositionals(
	args []string,
	optionsWithValues map[string]struct{},
	optionsWithoutValues map[string]struct{},
) ([]string, bool) {
	var values []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(values, args[i+1:]...), true
		}
		if strings.HasPrefix(arg, "--") {
			name, _, attached := strings.Cut(arg, "=")
			if _, consumes := optionsWithValues[name]; consumes {
				if !attached {
					if i+1 == len(args) || !separatedOptionValue(args[i+1]) {
						return nil, false
					}
					i++
				}
				continue
			}
			if _, known := optionsWithoutValues[name]; !known || attached {
				return nil, false
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			consumes, known := argparseShortOption(arg, optionsWithValues, optionsWithoutValues)
			if !known {
				return nil, false
			}
			if consumes {
				if i+1 == len(args) || !separatedOptionValue(args[i+1]) {
					return nil, false
				}
				i++
			}
			continue
		}
		values = append(values, arg)
	}
	return values, true
}

func parseArgparseApplication(
	args []string,
	optionsWithValues map[string]struct{},
	optionsWithoutValues map[string]struct{},
) PythonLaunch {
	positionals, ok := argparsePositionals(args, optionsWithValues, optionsWithoutValues)
	if !ok {
		return PythonLaunch{}
	}
	target := firstApplicationReference(positionals)
	if target == "" {
		return PythonLaunch{}
	}
	return PythonLaunch{Target: target, TargetKind: TargetModule, SearchPaths: []string{"."}}
}
