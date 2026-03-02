package ocihook

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMutateSpec_InjectsOnEligibleSpec(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SDKPackageVersion = "v0.0.7"
	cfg.HostInstrumentationDir = "/var/lib/beyla/instrumentation"
	cfg.OTLPEndpoint = "http://collector:4318"
	cfg.OTLPProtocol = "http/protobuf"
	cfg.EnabledSDKs = []Language{LanguageJava}

	spec := &Spec{Process: &ProcessSpec{Env: []string{"PATH=/usr/bin"}}}

	res, err := MutateSpec(spec, cfg)
	if err != nil {
		t.Fatalf("unexpected mutate error: %v", err)
	}
	if !res.Mutated {
		t.Fatalf("expected spec to be mutated")
	}

	env := strings.Join(spec.Process.Env, "\n")
	mustContain(t, env, "BEYLA_INJECTOR_SDK_PKG_VERSION=v0.0.7")
	mustContain(t, env, "LD_PRELOAD=/__otel_sdk_auto_instrumentation__/injector/libotelinject.so")
	mustContain(t, env, "OTEL_INJECTOR_CONFIG_FILE=/__otel_sdk_auto_instrumentation__/injector/otelinject.conf")
	mustContain(t, env, "OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318")
	mustContain(t, env, "OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf")
	mustContain(t, env, "OTEL_TRACES_EXPORTER=otlp")
	mustContain(t, env, "OTEL_METRICS_EXPORTER=otlp")
	mustContain(t, env, "OTEL_LOGS_EXPORTER=none")
	mustContain(t, env, "OTEL_SEMCONV_STABILITY_OPT_IN=http")
	mustContain(t, env, "DOTNET_AUTO_INSTRUMENTATION_AGENT_PATH_PREFIX=")
	mustContain(t, env, "NODEJS_AUTO_INSTRUMENTATION_AGENT_PATH=")
	mustContain(t, env, "PYTHON_AUTO_INSTRUMENTATION_AGENT_PATH_PREFIX=")

	if len(spec.Mounts) != 1 {
		t.Fatalf("expected one mount, got %d", len(spec.Mounts))
	}
	if got := spec.Mounts[0].Destination; got != cfg.InternalMountDir {
		t.Fatalf("unexpected mount destination: %s", got)
	}
	if got := spec.Mounts[0].Source; got != filepath.Join(cfg.HostInstrumentationDir, cfg.SDKPackageVersion) {
		t.Fatalf("unexpected mount source: %s", got)
	}
}

func TestMutateSpec_SkipsWhenForeignLDPreloadExists(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SDKPackageVersion = "v0.0.7"
	cfg.HostInstrumentationDir = "/var/lib/beyla/instrumentation"
	cfg.ExistingLDPreload = LDPreloadSkip

	spec := &Spec{Process: &ProcessSpec{Env: []string{"LD_PRELOAD=/tmp/other.so"}}}

	res, err := MutateSpec(spec, cfg)
	if err != nil {
		t.Fatalf("unexpected mutate error: %v", err)
	}
	if res.Mutated {
		t.Fatalf("expected mutation to be skipped")
	}
	if len(spec.Mounts) != 0 {
		t.Fatalf("expected no mounts to be injected")
	}
}

func TestMutateSpec_DoesNotOverrideExistingOTELByDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SDKPackageVersion = "v0.0.7"
	cfg.HostInstrumentationDir = "/var/lib/beyla/instrumentation"
	cfg.OTLPEndpoint = "http://collector:4318"

	spec := &Spec{Process: &ProcessSpec{Env: []string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://already-set:4318"}}}

	_, err := MutateSpec(spec, cfg)
	if err != nil {
		t.Fatalf("unexpected mutate error: %v", err)
	}
	env := strings.Join(spec.Process.Env, "\n")
	mustContain(t, env, "OTEL_EXPORTER_OTLP_ENDPOINT=http://already-set:4318")
	if strings.Contains(env, "OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318") {
		t.Fatalf("unexpected OTEL endpoint override when OverrideOTEL=false")
	}
}

func TestMutateSpec_IdempotentForSameVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SDKPackageVersion = "v0.0.7"
	cfg.HostInstrumentationDir = "/var/lib/beyla/instrumentation"

	spec := &Spec{Process: &ProcessSpec{Env: []string{
		"BEYLA_INJECTOR_SDK_PKG_VERSION=v0.0.7",
		"OTEL_INJECTOR_CONFIG_FILE=/__otel_sdk_auto_instrumentation__/injector/otelinject.conf",
		"LD_PRELOAD=/__otel_sdk_auto_instrumentation__/injector/libotelinject.so",
	}}}

	res, err := MutateSpec(spec, cfg)
	if err != nil {
		t.Fatalf("unexpected mutate error: %v", err)
	}
	if res.Mutated {
		t.Fatalf("expected already-instrumented container to skip mutation")
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected to find %q in env set", needle)
	}
}
