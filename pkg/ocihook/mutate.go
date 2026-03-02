package ocihook

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

const (
	envVarLdPreloadName            = "LD_PRELOAD"
	envVarLdPreloadValueSuffix     = "/injector/libotelinject.so"
	envOtelInjectorConfigFileName  = "OTEL_INJECTOR_CONFIG_FILE"
	envOtelInjectorConfigFileValue = "/injector/otelinject.conf"
	envVarSDKVersion               = "BEYLA_INJECTOR_SDK_PKG_VERSION"
	envOtelExporterEndpointName    = "OTEL_EXPORTER_OTLP_ENDPOINT"
	envOtelExporterProtocolName    = "OTEL_EXPORTER_OTLP_PROTOCOL"
	envOtelSemConvStabilityName    = "OTEL_SEMCONV_STABILITY_OPT_IN"
	envOtelTracesExporterName      = "OTEL_TRACES_EXPORTER"
	envOtelMetricsExporterName     = "OTEL_METRICS_EXPORTER"
	envOtelLogsExporterName        = "OTEL_LOGS_EXPORTER"

	envDotnetEnabledName = "DOTNET_AUTO_INSTRUMENTATION_AGENT_PATH_PREFIX"
	envJavaEnabledName   = "JVM_AUTO_INSTRUMENTATION_AGENT_PATH"
	envNodejsEnabledName = "NODEJS_AUTO_INSTRUMENTATION_AGENT_PATH"
	envPythonEnabledName = "PYTHON_AUTO_INSTRUMENTATION_AGENT_PATH_PREFIX"
)

type MutationResult struct {
	Mutated bool
	Reason  string
}

func MutateSpec(spec *Spec, cfg Config) (MutationResult, error) {
	if cfg.SDKPackageVersion == "" {
		return MutationResult{}, fmt.Errorf("sdk package version must not be empty")
	}
	if cfg.HostInstrumentationDir == "" {
		return MutationResult{}, fmt.Errorf("host instrumentation dir must not be empty")
	}
	if cfg.InternalMountDir == "" {
		return MutationResult{}, fmt.Errorf("internal mount dir must not be empty")
	}
	if spec == nil {
		return MutationResult{}, fmt.Errorf("spec is nil")
	}
	if spec.Process == nil {
		spec.Process = &ProcessSpec{}
	}

	envMap, order := envToMap(spec.Process.Env)
	injectorLibPath := cfg.InternalMountDir + envVarLdPreloadValueSuffix
	injectorConfigPath := cfg.InternalMountDir + envOtelInjectorConfigFileValue

	if preload, ok := envMap[envVarLdPreloadName]; ok && preload != "" && preload != injectorLibPath {
		switch cfg.ExistingLDPreload {
		case LDPreloadFail:
			return MutationResult{}, fmt.Errorf("existing LD_PRELOAD value %q is not managed by Beyla", preload)
		default:
			return MutationResult{Mutated: false, Reason: "existing non-Beyla LD_PRELOAD found, skipping"}, nil
		}
	}

	if envMap[envOtelInjectorConfigFileName] == injectorConfigPath && envMap[envVarSDKVersion] == cfg.SDKPackageVersion {
		return MutationResult{Mutated: false, Reason: "container already instrumented with requested SDK version"}, nil
	}

	mutated := false
	mutated = setEnvIfChanged(envMap, &order, envVarSDKVersion, cfg.SDKPackageVersion, true) || mutated
	mutated = setEnvIfChanged(envMap, &order, envVarLdPreloadName, injectorLibPath, true) || mutated
	mutated = setEnvIfChanged(envMap, &order, envOtelInjectorConfigFileName, injectorConfigPath, !cfg.OverrideOTEL) || mutated

	if cfg.OTLPEndpoint != "" {
		mutated = setEnvIfChanged(envMap, &order, envOtelExporterEndpointName, cfg.OTLPEndpoint, !cfg.OverrideOTEL) || mutated
	}
	if cfg.OTLPProtocol != "" {
		mutated = setEnvIfChanged(envMap, &order, envOtelExporterProtocolName, cfg.OTLPProtocol, !cfg.OverrideOTEL) || mutated
	}
	// Keep exporter behavior explicit in the runtime path, mirroring webhook behavior.
	// Users can still predefine these values and keep them when OverrideOTEL=false.
	mutated = setEnvIfChanged(envMap, &order, envOtelTracesExporterName, "otlp", !cfg.OverrideOTEL) || mutated
	mutated = setEnvIfChanged(envMap, &order, envOtelMetricsExporterName, "otlp", !cfg.OverrideOTEL) || mutated
	mutated = setEnvIfChanged(envMap, &order, envOtelLogsExporterName, "none", !cfg.OverrideOTEL) || mutated
	mutated = setEnvIfChanged(envMap, &order, envOtelSemConvStabilityName, "http", !cfg.OverrideOTEL) || mutated

	for language, envName := range disabledSDKEnvVars(cfg.EnabledSDKs) {
		_ = language // keep language mapping explicit in this loop for future debugging hooks
		mutated = setEnvIfChanged(envMap, &order, envName, "", true) || mutated
	}

	spec.Process.Env = mapToEnv(envMap, order)
	if ensureInjectMount(spec, cfg) {
		mutated = true
	}

	if !mutated {
		return MutationResult{Mutated: false, Reason: "no changes required"}, nil
	}

	return MutationResult{Mutated: true, Reason: "spec mutated"}, nil
}

func ensureInjectMount(spec *Spec, cfg Config) bool {
	source := filepath.Join(cfg.HostInstrumentationDir, cfg.SDKPackageVersion)
	target := cfg.InternalMountDir
	mount := MountSpec{
		Destination: target,
		Source:      source,
		Type:        "bind",
		Options:     []string{"rbind", "ro", "nosuid", "nodev"},
	}

	for i := range spec.Mounts {
		if spec.Mounts[i].Destination == target {
			if mountsEqual(spec.Mounts[i], mount) {
				return false
			}
			spec.Mounts[i] = mount
			return true
		}
	}

	spec.Mounts = append(spec.Mounts, mount)
	return true
}

func mountsEqual(a, b MountSpec) bool {
	if a.Destination != b.Destination || a.Source != b.Source || a.Type != b.Type {
		return false
	}
	return slices.Equal(a.Options, b.Options)
}

func envToMap(env []string) (map[string]string, []string) {
	m := make(map[string]string, len(env))
	order := make([]string, 0, len(env))

	for _, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.TrimSpace(parts[0]), parts[1]
		if key == "" {
			continue
		}
		if _, exists := m[key]; !exists {
			order = append(order, key)
		}
		m[key] = value
	}

	return m, order
}

func mapToEnv(m map[string]string, order []string) []string {
	out := make([]string, 0, len(m))
	seen := make(map[string]struct{}, len(order))

	for _, key := range order {
		value, ok := m[key]
		if !ok {
			continue
		}
		out = append(out, key+"="+value)
		seen[key] = struct{}{}
	}

	remaining := make([]string, 0, len(m)-len(order))
	for key := range maps.Keys(m) {
		if _, ok := seen[key]; ok {
			continue
		}
		remaining = append(remaining, key)
	}
	slices.Sort(remaining)
	for _, key := range remaining {
		out = append(out, key+"="+m[key])
	}

	return out
}

func setEnvIfChanged(env map[string]string, order *[]string, key, value string, preserveIfPresent bool) bool {
	current, exists := env[key]
	if exists && preserveIfPresent {
		return false
	}
	if exists && current == value {
		return false
	}

	if !exists {
		*order = append(*order, key)
	}
	env[key] = value
	return true
}

func disabledSDKEnvVars(enabled []Language) map[Language]string {
	enabledSet := make(map[Language]struct{}, len(enabled))
	for _, language := range enabled {
		enabledSet[language] = struct{}{}
	}

	disable := map[Language]string{}
	all := map[Language]string{
		LanguageDotnet: envDotnetEnabledName,
		LanguageJava:   envJavaEnabledName,
		LanguageNodeJS: envNodejsEnabledName,
		LanguagePython: envPythonEnabledName,
	}
	for language, envName := range all {
		if _, ok := enabledSet[language]; !ok {
			disable[language] = envName
		}
	}

	return disable
}
