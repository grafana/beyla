// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks // import "go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"

func ParseDaphne(args []string) PythonLaunch {
	return parseArgparseApplication(args, daphneOptionsWithValues, daphneOptionsWithoutValues)
}

var daphneOptionsWithValues = optionSet(
	"-p", "--port", "-b", "--bind", "--websocket_timeout", "--websocket_connect_timeout", "-u",
	"--unix-socket", "--fd", "-e", "--endpoint", "-v", "--verbosity", "-t", "--http-timeout",
	"--access-log", "--log-fmt", "--ping-interval", "--ping-timeout", "--websocket-max-message-size",
	"--websocket-max-frame-size", "--application-close-timeout", "--root-path", "--proxy-headers-host",
	"--proxy-headers-port", "-s", "--server-name",
)

var daphneOptionsWithoutValues = optionSet(
	"--proxy-headers", "--no-server-name", "-h", "--help",
)
