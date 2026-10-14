package lang

import "strings"

const coreclrEnableProfilingEnvVar = "CORECLR_ENABLE_PROFILING"

// DotnetInstrumentationEnvVars lists the environment variables whose presence
// indicates that a .NET process has profiling, startup hooks, an additional
// deps store, or OpenTelemetry .NET auto-instrumentation configured.
var DotnetInstrumentationEnvVars = []string{
	coreclrEnableProfilingEnvVar,
	"CORECLR_PROFILER",
	"CORECLR_PROFILER_PATH",
	"DOTNET_ADDITIONAL_DEPS",
	"DOTNET_SHARED_STORE",
	"DOTNET_STARTUP_HOOKS",
	"OTEL_DOTNET_AUTO_HOME",
}

// HasDotnetInstrumentation reports whether any of the well-known .NET
// instrumentation environment variables are set to a meaningful value.
// Values are trimmed of surrounding whitespace before evaluation; a var that
// trims to the empty string is treated as unset. CORECLR_ENABLE_PROFILING
// must additionally be exactly "1" to count as enabled (the CLR's own rule).
func HasDotnetInstrumentation(env map[string]string) bool {
	for _, name := range DotnetInstrumentationEnvVars {
		val := strings.TrimSpace(env[name])
		if val == "" {
			continue
		}
		if name == coreclrEnableProfilingEnvVar && val != "1" {
			continue
		}
		return true
	}
	return false
}
