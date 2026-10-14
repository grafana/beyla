// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import "strings"

func ParseHypercorn(args []string) PythonLaunch {
	positionals, ok := argparsePositionals(args, hypercornOptionsWithValues, hypercornOptionsWithoutValues)
	if !ok || len(positionals) != 1 {
		return PythonLaunch{}
	}
	target, kind, ok := hypercornApplication(positionals[0])
	if !ok {
		return PythonLaunch{}
	}
	return PythonLaunch{Target: target, TargetKind: kind, SearchPaths: []string{"."}}
}

func hypercornApplication(application string) (string, TargetKind, bool) {
	if CleanValue(application) != application {
		return "", TargetNone, false
	}

	module := application
	object := ""
	switch strings.Count(application, ":") {
	case 0:
	case 2:
		mode, remainder, _ := strings.Cut(application, ":")
		if mode != "asgi" && mode != "wsgi" {
			return "", TargetNone, false
		}
		module, object, _ = strings.Cut(remainder, ":")
	default:
		module, object, _ = strings.Cut(application, ":")
	}
	if module == "" || strings.Contains(application, ":") && object == "" {
		return "", TargetNone, false
	}

	kind := ClassifyTarget(module)
	if kind == TargetModule && !validModule(module) {
		return "", TargetNone, false
	}
	target := module
	if object != "" {
		target += ":" + object
	}
	return target, kind, true
}

var hypercornOptionsWithValues = optionSet(
	"--access-log", "--access-logfile", "--access-logformat", "--backlog", "-b", "--bind", "--ca-certs",
	"--certfile", "--cert-reqs", "--ciphers", "-c", "--config", "--error-log", "--error-logfile", "--log-file",
	"--graceful-timeout", "--read-timeout", "--max-requests", "--max-requests-jitter", "-g", "--group", "-k",
	"--worker-class", "--keep-alive", "--keyfile", "--keyfile-password", "--insecure-bind", "--log-config",
	"--log-level", "-p", "--pid", "--quic-bind", "--root-path", "--server-name", "--statsd-host",
	"--statsd-prefix", "-m", "--umask", "-u", "--user", "--verify-mode", "--websocket-ping-interval", "-w",
	"--workers",
)

var hypercornOptionsWithoutValues = optionSet(
	"-D", "--daemon", "--debug", "--reload", "-h", "--help",
)
