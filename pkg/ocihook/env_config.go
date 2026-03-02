package ocihook

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

func ConfigFromEnv() (Config, error) {
	cfg := DefaultConfig()

	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_DELEGATE_RUNTIME")); v != "" {
		cfg.DelegateRuntime = v
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_MODE")); v != "" {
		cfg.Mode = Mode(v)
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_LOG_LEVEL")); v != "" {
		cfg.LogLevel = strings.ToLower(v)
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_DECISION_REPORT")); v != "" {
		cfg.DecisionReport = strings.ToLower(v)
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_EXISTING_LD_PRELOAD")); v != "" {
		cfg.ExistingLDPreload = ExistingLDPreloadAction(v)
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_SDK_PACKAGE_VERSION")); v != "" {
		cfg.SDKPackageVersion = v
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_HOST_INSTRUMENTATION_DIR")); v != "" {
		cfg.HostInstrumentationDir = v
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_INTERNAL_MOUNT_DIR")); v != "" {
		cfg.InternalMountDir = v
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_OPTIN_ANNOTATION")); v != "" {
		cfg.Policy.OptInAnnotation = v
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_OPTIN_ENV_VAR")); v != "" {
		cfg.Policy.OptInEnvVar = v
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_OTLP_ENDPOINT")); v != "" {
		cfg.OTLPEndpoint = v
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_OTLP_PROTOCOL")); v != "" {
		cfg.OTLPProtocol = v
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_MUTATE_COMMANDS")); v != "" {
		cfg.MutateCommands = splitCSV(v)
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_ENABLED_SDKS")); v != "" {
		cfg.EnabledSDKs = parseLanguages(v)
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_OVERRIDE_OTEL")); v != "" {
		cfg.OverrideOTEL = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
	}
	if v := strings.TrimSpace(os.Getenv("BEYLA_OCI_DRY_RUN")); v != "" {
		cfg.DryRun = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
	}

	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func validateConfig(cfg Config) error {
	if cfg.Mode != ModePermissive && cfg.Mode != ModeStrict {
		return fmt.Errorf("invalid BEYLA_OCI_MODE %q", cfg.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.LogLevel)) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid BEYLA_OCI_LOG_LEVEL %q", cfg.LogLevel)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.DecisionReport)) {
	case "none", "stderr", "stdout":
	default:
		return fmt.Errorf("invalid BEYLA_OCI_DECISION_REPORT %q", cfg.DecisionReport)
	}
	if cfg.ExistingLDPreload != LDPreloadSkip && cfg.ExistingLDPreload != LDPreloadFail {
		return fmt.Errorf("invalid BEYLA_OCI_EXISTING_LD_PRELOAD %q", cfg.ExistingLDPreload)
	}
	if strings.TrimSpace(cfg.DelegateRuntime) == "" {
		return fmt.Errorf("delegate runtime must not be empty")
	}
	if len(cfg.MutateCommands) == 0 {
		return fmt.Errorf("mutate commands must not be empty")
	}
	if strings.TrimSpace(cfg.Policy.OptInAnnotation) == "" && strings.TrimSpace(cfg.Policy.OptInEnvVar) == "" {
		return fmt.Errorf("at least one selection key must be configured (annotation or env var)")
	}

	return nil
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseLanguages(v string) []Language {
	langs := make([]Language, 0, 4)
	for _, item := range splitCSV(v) {
		lang := Language(strings.ToLower(item))
		switch lang {
		case LanguageJava, LanguageDotnet, LanguageNodeJS, LanguagePython:
			if !slices.Contains(langs, lang) {
				langs = append(langs, lang)
			}
		}
	}
	return langs
}
