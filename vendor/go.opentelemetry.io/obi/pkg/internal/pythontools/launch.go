// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools // import "go.opentelemetry.io/obi/pkg/internal/pythontools"

import (
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"
)

const interpreterOptionsWithoutValues = "bBdEhiIOPqRsStuvVx?"

var nonApplicationModules = map[string]struct{}{
	"ensurepip":   {},
	"http.server": {},
	"idlelib":     {},
	"pip":         {},
	"pydoc":       {},
	"pytest":      {},
	"unittest":    {},
	"venv":        {},
}

func commandName(path string) string {
	name := strings.ToLower(filepath.Base(path))
	return strings.TrimSuffix(name, filepath.Ext(name))
}

func isPythonInterpreter(command string) bool {
	return strings.HasPrefix(command, "python") || strings.HasPrefix(command, "pypy")
}

func parsePythonLaunch(executable string, args []string, env map[string]string) frameworks.PythonLaunch {
	command := commandName(executable)
	if isPythonInterpreter(command) {
		return parseInterpreterLaunch(args, env)
	}
	if launch, ok := parseLauncher(command, args, env); ok {
		return launch
	}
	return frameworks.PythonLaunch{}
}

func parseInterpreterLaunch(args []string, env map[string]string) frameworks.PythonLaunch {
	pathConfig := frameworks.PythonPathConfig{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			if i+1 < len(args) {
				return pathConfig.Apply(launchForScript(args[i+1], args[i+2:], env))
			}
			return frameworks.PythonLaunch{}
		case arg == "-":
			return frameworks.PythonLaunch{}
		case arg == "--check-hash-based-pycs":
			i++
			continue
		case strings.HasPrefix(arg, "--"):
			continue
		case strings.HasPrefix(arg, "-"):
			if launch, done := parseInterpreterShortOptions(arg[1:], args, &i, env, &pathConfig); done {
				return pathConfig.Apply(launch)
			}
		default:
			return pathConfig.Apply(launchForScript(arg, args[i+1:], env))
		}
	}
	return frameworks.PythonLaunch{}
}

func parseInterpreterShortOptions(
	options string,
	args []string,
	index *int,
	env map[string]string,
	pathConfig *frameworks.PythonPathConfig,
) (frameworks.PythonLaunch, bool) {
	for optionIndex := 0; optionIndex < len(options); optionIndex++ {
		option := options[optionIndex]
		switch option {
		case 'E':
			pathConfig.IgnorePythonEnvironment = true
		case 'I':
			pathConfig.IgnorePythonEnvironment = true
			pathConfig.SafePath = true
		case 'P':
			pathConfig.SafePath = true
		case 'c':
			return frameworks.PythonLaunch{}, true
		case 'm':
			module := options[optionIndex+1:]
			if module == "" {
				(*index)++
				if *index >= len(args) {
					return frameworks.PythonLaunch{}, true
				}
				module = args[*index]
			}
			return launchForModule(module, args[*index+1:], env), true
		case 'W', 'X':
			if optionIndex+1 == len(options) {
				(*index)++
				if *index >= len(args) {
					return frameworks.PythonLaunch{}, true
				}
			}
			return frameworks.PythonLaunch{}, false
		default:
			if !strings.ContainsRune(interpreterOptionsWithoutValues, rune(option)) {
				return frameworks.PythonLaunch{}, true
			}
		}
	}
	return frameworks.PythonLaunch{}, false
}

func launchForModule(module string, args []string, env map[string]string) frameworks.PythonLaunch {
	if launch, ok := parseLauncher(module, args, env); ok {
		return launch
	}
	if _, excluded := nonApplicationModules[module]; excluded {
		return frameworks.PythonLaunch{}
	}
	return frameworks.PythonLaunch{Target: module, TargetKind: frameworks.TargetRunnableModule}
}

func launchForScript(script string, args []string, env map[string]string) frameworks.PythonLaunch {
	command := commandName(script)
	if launch, ok := parseLauncher(command, args, env); ok {
		return launch
	}
	if command == "manage" {
		launch := frameworks.ParseDjango(args, env)
		if launch.Target == "" {
			launch.Target = script
			launch.TargetKind = frameworks.TargetScriptPath
		} else {
			launch.ScriptDir = filepath.Dir(script)
		}
		return launch
	}
	if script == "-" {
		return frameworks.PythonLaunch{}
	}
	return frameworks.PythonLaunch{Target: script, TargetKind: frameworks.TargetScriptPath}
}

func parseLauncher(command string, args []string, env map[string]string) (frameworks.PythonLaunch, bool) {
	switch command {
	case "gunicorn":
		return frameworks.ParseGunicorn(args, env), true
	case "uvicorn":
		return frameworks.ParseUvicorn(args, env), true
	case "hypercorn":
		return frameworks.ParseHypercorn(args), true
	case "daphne":
		return frameworks.ParseDaphne(args), true
	case "uwsgi":
		return frameworks.ParseUWSGI(args), true
	case "waitress", "waitress-serve", "waitress_serve":
		return frameworks.ParseWaitress(args), true
	case "flask":
		return frameworks.ParseFlask(args, env), true
	case "fastapi":
		return frameworks.ParseFastAPI(args), true
	case "django", "django-admin", "django_admin":
		return frameworks.ParseDjango(args, env), true
	case "celery":
		return frameworks.ParseCelery(args, env), true
	default:
		return frameworks.PythonLaunch{}, false
	}
}
