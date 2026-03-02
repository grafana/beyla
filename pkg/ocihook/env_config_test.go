package ocihook

import "testing"

func TestConfigFromEnv_ParsesValues(t *testing.T) {
	t.Setenv("BEYLA_OCI_MODE", "strict")
	t.Setenv("BEYLA_OCI_LOG_LEVEL", "debug")
	t.Setenv("BEYLA_OCI_DECISION_REPORT", "stdout")
	t.Setenv("BEYLA_OCI_EXISTING_LD_PRELOAD", "fail")
	t.Setenv("BEYLA_OCI_DELEGATE_RUNTIME", "/usr/local/bin/runc")
	t.Setenv("BEYLA_OCI_MUTATE_COMMANDS", "create,run")
	t.Setenv("BEYLA_OCI_ENABLED_SDKS", "java,nodejs,unknown,nodejs")
	t.Setenv("BEYLA_OCI_OVERRIDE_OTEL", "true")
	t.Setenv("BEYLA_OCI_DRY_RUN", "yes")
	t.Setenv("BEYLA_OCI_OPTIN_ENV_VAR", "MY_CUSTOM_INJECT")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error loading config from env: %v", err)
	}

	if cfg.Mode != ModeStrict {
		t.Fatalf("expected strict mode, got %q", cfg.Mode)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected debug log level, got %q", cfg.LogLevel)
	}
	if cfg.DecisionReport != "stdout" {
		t.Fatalf("expected stdout decision report mode, got %q", cfg.DecisionReport)
	}
	if cfg.ExistingLDPreload != LDPreloadFail {
		t.Fatalf("expected fail preload behavior, got %q", cfg.ExistingLDPreload)
	}
	if cfg.DelegateRuntime != "/usr/local/bin/runc" {
		t.Fatalf("unexpected delegate runtime: %q", cfg.DelegateRuntime)
	}
	if len(cfg.MutateCommands) != 2 || cfg.MutateCommands[0] != "create" || cfg.MutateCommands[1] != "run" {
		t.Fatalf("unexpected mutate commands: %#v", cfg.MutateCommands)
	}
	if len(cfg.EnabledSDKs) != 2 || cfg.EnabledSDKs[0] != LanguageJava || cfg.EnabledSDKs[1] != LanguageNodeJS {
		t.Fatalf("unexpected enabled SDKs: %#v", cfg.EnabledSDKs)
	}
	if !cfg.OverrideOTEL {
		t.Fatalf("expected override otel to be true")
	}
	if !cfg.DryRun {
		t.Fatalf("expected dry run to be true")
	}
	if cfg.Policy.OptInEnvVar != "MY_CUSTOM_INJECT" {
		t.Fatalf("unexpected opt-in env var key: %q", cfg.Policy.OptInEnvVar)
	}
}

func TestConfigFromEnv_RejectsInvalidMode(t *testing.T) {
	t.Setenv("BEYLA_OCI_MODE", "invalid")

	_, err := ConfigFromEnv()
	if err == nil {
		t.Fatalf("expected validation error for invalid mode")
	}
}

func TestConfigFromEnv_RejectsInvalidLogLevel(t *testing.T) {
	t.Setenv("BEYLA_OCI_LOG_LEVEL", "trace")

	_, err := ConfigFromEnv()
	if err == nil {
		t.Fatalf("expected validation error for invalid log level")
	}
}

func TestConfigFromEnv_RejectsInvalidDecisionReport(t *testing.T) {
	t.Setenv("BEYLA_OCI_DECISION_REPORT", "file")

	_, err := ConfigFromEnv()
	if err == nil {
		t.Fatalf("expected validation error for invalid decision report")
	}
}
