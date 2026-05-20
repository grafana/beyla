package lang

import "strings"

const (
	nodeAutoInstrumentationModule = "@opentelemetry/auto-instrumentations-node/register"
	nodeOptionsEnvVar             = "NODE_OPTIONS"
)

var nodeRequireFlags = []string{"--require", "-r"}

// HasNodeJSAutoInstrumentation reports whether the OpenTelemetry Node.js
// auto-instrumentation register hook is present, either as a "--require" flag
// on the process command line or inside the NODE_OPTIONS environment variable.
// Both "--require X" and "--require=X" forms are recognized.
func HasNodeJSAutoInstrumentation(cmdline []string, env map[string]string) bool {
	if argsContainNodeAutoInstrumentation(cmdline) {
		return true
	}
	if val, ok := env[nodeOptionsEnvVar]; ok && val != "" {
		if argsContainNodeAutoInstrumentation(strings.Fields(val)) {
			return true
		}
	}
	return false
}

func argsContainNodeAutoInstrumentation(args []string) bool {
	for i, a := range args {
		if isRequireFlag(a) {
			if i+1 < len(args) && args[i+1] == nodeAutoInstrumentationModule {
				return true
			}
			continue
		}
		for _, flag := range nodeRequireFlags {
			if a == flag+"="+nodeAutoInstrumentationModule {
				return true
			}
		}
	}
	return false
}

func isRequireFlag(s string) bool {
	for _, flag := range nodeRequireFlags {
		if s == flag {
			return true
		}
	}
	return false
}
