// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import (
	"path/filepath"
	"slices"
	"strings"
)

func ParseGunicorn(args []string, env map[string]string) PythonLaunch {
	var settings gunicornSettings
	fields, ok := splitShellFields(env["GUNICORN_CMD_ARGS"])
	if !ok {
		return PythonLaunch{}
	}
	if _, ok := gunicornPositionals(fields); !ok {
		return PythonLaunch{}
	}
	positionals, ok := gunicornPositionals(args)
	if !ok {
		return PythonLaunch{}
	}

	applyGunicornSettings(fields, &settings)
	applyGunicornSettings(args, &settings)

	launch := PythonLaunch{FallbackName: CleanValue(settings.name)}

	chdir := settings.chdir
	if chdir == "" {
		chdir = "."
	}

	pythonPaths := splitList(settings.pythonPath)

	for _, path := range slices.Backward(pythonPaths) {

		if !filepath.IsAbs(path) {
			path = filepath.Join(chdir, path)
		}
		launch.SearchPaths = append(launch.SearchPaths, path)
	}

	launch.SearchPaths = append(launch.SearchPaths, chdir)

	if target, ok := gunicornApplication(positionals); ok {
		launch.Target = target
		launch.TargetKind = TargetModule
	}

	return launch
}

func gunicornApplication(positionals []string) (string, bool) {
	if len(positionals) == 0 {
		return "", false
	}

	target := positionals[0]

	if CleanValue(target) != target || !validModule(target) && !isApplicationReference(target) {
		return "", false
	}

	return target, true
}

type gunicornSettings struct {
	chdir      string
	pythonPath string
	name       string
}

func applyGunicornSettings(args []string, settings *gunicornSettings) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return
		case arg == "--chdir" && i+1 < len(args):
			i++
			settings.chdir = args[i]
		case strings.HasPrefix(arg, "--chdir="):
			settings.chdir = strings.TrimPrefix(arg, "--chdir=")
		case arg == "--pythonpath" && i+1 < len(args):
			i++
			settings.pythonPath = args[i]
		case strings.HasPrefix(arg, "--pythonpath="):
			settings.pythonPath = strings.TrimPrefix(arg, "--pythonpath=")
		case (arg == "-n" || arg == "--name") && i+1 < len(args):
			i++
			settings.name = args[i]
		case strings.HasPrefix(arg, "--name="):
			settings.name = strings.TrimPrefix(arg, "--name=")
		case strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--"):
			if name, ok := gunicornAttachedShortValue(arg, "-n"); ok {
				settings.name = name
			}
		}
	}
}

func gunicornPositionals(args []string) ([]string, bool) {
	var values []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(values, args[i+1:]...), true
		}
		if strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(arg, "=")
			if name == "--proxy-protocol" {
				if attached {
					if !gunicornProxyProtocolMode(value) {
						return nil, false
					}
				} else if i+1 < len(args) && gunicornProxyProtocolMode(args[i+1]) {
					i++
				}
				continue
			}
			if _, consumes := gunicornOptionsWithValues[name]; consumes {
				if !attached {
					if i+1 == len(args) {
						return nil, false
					}
					i++
				}
				continue
			}
			if _, known := gunicornOptionsWithoutValues[name]; !known || attached {
				return nil, false
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			consumes, known := argparseShortOption(arg, gunicornOptionsWithValues, gunicornOptionsWithoutValues)
			if !known {
				return nil, false
			}
			if consumes {
				if i+1 == len(args) {
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

func gunicornProxyProtocolMode(value string) bool {
	switch value {
	case "off", "v1", "v2", "auto":
		return true
	default:
		return false
	}
}

func gunicornAttachedShortValue(arg, target string) (string, bool) {
	for i := 1; i < len(arg); i++ {
		name := "-" + arg[i:i+1]
		if _, known := gunicornOptionsWithoutValues[name]; known {
			continue
		}
		if _, consumes := gunicornOptionsWithValues[name]; consumes && name == target && i+1 < len(arg) {
			return strings.TrimPrefix(arg[i+1:], "="), true
		}
		return "", false
	}
	return "", false
}

var gunicornOptionsWithValues = optionSet(
	"-c", "--config", "-b", "--bind", "--backlog", "-w", "--workers", "-k", "--worker-class", "--threads",
	"--worker-connections", "--max-requests", "--max-requests-jitter", "-t", "--timeout", "--graceful-timeout",
	"--keep-alive", "--limit-request-line", "--limit-request-fields", "--limit-request-field_size",
	"--reload-engine", "--reload-extra-file", "--chdir", "-e", "--env", "-p", "--pid", "--worker-tmp-dir",
	"-u", "--user", "-g", "--group", "-m", "--umask", "--forwarded-allow-ips", "--access-logfile",
	"--access-logformat", "--error-logfile", "--log-file", "--log-level", "--logger-class", "--log-config",
	"--log-config-json", "--log-syslog-to", "--log-syslog-prefix", "--log-syslog-facility", "--statsd-host",
	"--dogstatsd-tags", "--statsd-prefix", "-n", "--name", "--pythonpath", "--paste", "--paster",
	"--proxy-allow-from", "--protocol", "--uwsgi-allow-from", "--keyfile", "--certfile", "--ssl-version",
	"--cert-reqs", "--ca-certs", "--ciphers", "--http-protocols", "--http2-cleartext",
	"--http2-max-concurrent-streams", "--http2-initial-window-size", "--http2-max-frame-size",
	"--http2-max-header-list-size", "--paste-global", "--forwarder-headers", "--header-map", "--asgi-loop",
	"--asgi-lifespan", "--asgi-disconnect-grace-period", "--http-parser", "--root-path", "--dirty-app",
	"--dirty-workers", "--dirty-timeout", "--dirty-threads", "--dirty-graceful-timeout", "--control-socket",
	"--control-socket-mode",
)

var gunicornOptionsWithoutValues = optionSet(
	"--reload", "--spew", "--check-config", "--print-config", "--preload", "--no-sendfile", "--reuse-port",
	"-D", "--daemon", "--initgroups", "--disable-redirect-access-to-syslog", "--capture-output",
	"--log-syslog", "-R", "--enable-stdio-inheritance", "--enable-backlog-metric", "--suppress-ragged-eofs",
	"--do-handshake-on-connect", "--permit-obsolete-folding", "--strip-header-spaces",
	"--permit-unconventional-http-method", "--permit-unconventional-http-version", "--casefold-http-method",
	"--no-control-socket", "-h", "--help", "-v", "--version", "--proxy-protocol",
)
