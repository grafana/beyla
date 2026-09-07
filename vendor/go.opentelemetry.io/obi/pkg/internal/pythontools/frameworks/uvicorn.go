// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import "strings"

func ParseUvicorn(args []string, env map[string]string) PythonLaunch {
	positionals, ok := uvicornPositionals(args)
	if !ok {
		return PythonLaunch{}
	}

	appDir := env["UVICORN_APP_DIR"]

options:
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--":
			break options
		case args[i] == "--app-dir" && i+1 < len(args):
			i++
			appDir = args[i]
		case strings.HasPrefix(args[i], "--app-dir="):
			appDir = strings.TrimPrefix(args[i], "--app-dir=")
		}
	}
	if appDir == "" {
		appDir = "."
	}

	launch := PythonLaunch{SearchPaths: []string{appDir}}
	if target := firstApplicationReference(positionals); target != "" {
		launch.Target = target
		launch.TargetKind = TargetModule
		return launch
	}
	if target := CleanValue(env["UVICORN_APP"]); target != "" {
		launch.Target = target
		launch.TargetKind = TargetModule
	}
	return launch
}

func uvicornPositionals(args []string) ([]string, bool) {
	var values []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(values, args[i+1:]...), true
		}
		if strings.HasPrefix(arg, "--") {
			name, _, attached := strings.Cut(arg, "=")
			if _, consumes := uvicornOptionsWithValues[name]; consumes {
				if !attached {
					if i+1 == len(args) {
						return nil, false
					}
					i++
				}
				continue
			}
			if _, known := uvicornOptionsWithoutValues[name]; !known || attached {
				return nil, false
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			return nil, false
		}
		values = append(values, arg)
	}
	return values, true
}

var uvicornOptionsWithValues = optionSet(
	"--host", "--port", "--uds", "--fd", "--reload-dir", "--reload-delay", "--reload-include", "--reload-exclude",
	"--workers", "--env-file", "--timeout-worker-healthcheck", "--log-config", "--log-level", "--loop", "--http",
	"--ws", "--ws-max-size", "--ws-max-queue", "--ws-ping-interval", "--ws-ping-timeout", "--ws-per-message-deflate",
	"--lifespan", "--h11-max-incomplete-event-size", "--interface", "--root-path", "--forwarded-allow-ips", "--header",
	"--ssl-keyfile", "--ssl-keyfile-password", "--ssl-certfile", "--ssl-version", "--ssl-cert-reqs", "--ssl-ca-certs",
	"--ssl-ciphers", "--app-dir", "--limit-concurrency", "--backlog", "--limit-max-requests",
	"--limit-max-requests-jitter", "--timeout-keep-alive", "--timeout-graceful-shutdown",
)

var uvicornOptionsWithoutValues = optionSet(
	"--reload", "--access-log", "--no-access-log", "--use-colors", "--no-use-colors", "--proxy-headers",
	"--no-proxy-headers", "--server-header", "--no-server-header", "--date-header", "--no-date-header",
	"--version", "--reset-contextvars", "--factory", "--help",
)
