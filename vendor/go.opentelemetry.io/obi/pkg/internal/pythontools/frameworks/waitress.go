// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

import "strings"

func ParseWaitress(args []string) PythonLaunch {
	target, ok := waitressApplication(args)
	if !ok || CleanValue(target) != target {
		return PythonLaunch{}
	}
	switch {
	case isStrictApplicationReference(target):
		return PythonLaunch{Target: target, TargetKind: TargetModule}
	case strings.Contains(target, ".") && validModule(target):
		return PythonLaunch{Target: target, TargetKind: TargetDottedReference}
	default:
		return PythonLaunch{}
	}
}

func waitressApplication(args []string) (string, bool) {
	var app string
	var positionals []string

options:
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			positionals = append(positionals, args[i+1:]...)
			break options
		case !strings.HasPrefix(arg, "-") || arg == "-":
			positionals = append(positionals, args[i:]...)
			break options
		case !strings.HasPrefix(arg, "--"):
			return "", false
		}

		name, value, attached := strings.Cut(arg, "=")
		if _, consumes := waitressOptionsWithValues[name]; consumes {
			if !attached {
				if i+1 == len(args) || !separatedOptionValue(args[i+1]) {
					return "", false
				}
				i++
				value = args[i]
			}
			if name == "--app" {
				app = value
			}
			continue
		}
		if _, known := waitressOptionsWithoutValues[name]; !known || attached {
			return "", false
		}
	}

	if app != "" {
		return app, len(positionals) == 0
	}
	if len(positionals) != 1 {
		return "", false
	}
	return positionals[0], true
}

var waitressOptionsWithValues = optionSet(
	"--host", "--port", "--listen", "--threads", "--trusted-proxy", "--trusted-proxy-count",
	"--trusted-proxy-headers", "--url-scheme", "--url-prefix", "--backlog", "--recv-bytes", "--send-bytes",
	"--outbuf-overflow", "--outbuf-high-watermark", "--inbuf-overflow", "--connection-limit",
	"--cleanup-interval", "--channel-timeout", "--max-request-header-size", "--max-request-body-size",
	"--ident", "--asyncore-loop-timeout", "--unix-socket", "--unix-socket-perms", "--sockets",
	"--channel-request-lookahead", "--server-name", "--app",
)

var waitressOptionsWithoutValues = optionSet(
	"--help", "--call", "--ipv4", "--no-ipv4", "--ipv6", "--no-ipv6", "--log-untrusted-proxy-headers",
	"--no-log-untrusted-proxy-headers", "--clear-untrusted-proxy-headers", "--no-clear-untrusted-proxy-headers",
	"--log-socket-errors", "--no-log-socket-errors", "--expose-tracebacks", "--no-expose-tracebacks",
	"--asyncore-use-poll", "--no-asyncore-use-poll",
)
