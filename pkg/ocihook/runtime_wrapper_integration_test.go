package ocihook

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrapperExecute_IntegrationMutatesSpecOnDisk(t *testing.T) {
	bundle := t.TempDir()
	initial := &Spec{
		Annotations: map[string]string{"beyla.grafana.com/inject": "true"},
		Process: &ProcessSpec{
			Env: []string{"PATH=/usr/bin"},
		},
		Mounts: []MountSpec{},
	}
	if err := SaveSpec(bundle, initial); err != nil {
		t.Fatalf("write initial spec: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SDKPackageVersion = "v0.0.9"
	cfg.HostInstrumentationDir = "/var/lib/beyla/instrumentation"
	cfg.OTLPEndpoint = "http://collector:4318"
	cfg.OTLPProtocol = "http/protobuf"

	w := NewWrapper(cfg)
	w.run = func(context.Context, string, []string) error { return nil }

	if err := w.Execute(context.Background(), []string{"create", "--bundle", bundle, "test-container"}); err != nil {
		t.Fatalf("execute wrapper: %v", err)
	}

	finalSpec, err := LoadSpec(bundle)
	if err != nil {
		t.Fatalf("read final spec: %v", err)
	}

	env := strings.Join(finalSpec.Process.Env, "\n")
	mustContainIntegration(t, env, "BEYLA_INJECTOR_SDK_PKG_VERSION=v0.0.9")
	mustContainIntegration(t, env, "LD_PRELOAD=/__otel_sdk_auto_instrumentation__/injector/libotelinject.so")
	mustContainIntegration(t, env, "OTEL_INJECTOR_CONFIG_FILE=/__otel_sdk_auto_instrumentation__/injector/otelinject.conf")
	mustContainIntegration(t, env, "OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318")
	mustContainIntegration(t, env, "OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf")

	if len(finalSpec.Mounts) != 1 {
		t.Fatalf("expected one injected mount, got %d", len(finalSpec.Mounts))
	}
	if finalSpec.Mounts[0].Destination != cfg.InternalMountDir {
		t.Fatalf("unexpected mount destination %q", finalSpec.Mounts[0].Destination)
	}
	wantSource := filepath.Join(cfg.HostInstrumentationDir, cfg.SDKPackageVersion)
	if finalSpec.Mounts[0].Source != wantSource {
		t.Fatalf("unexpected mount source %q", finalSpec.Mounts[0].Source)
	}
}

func TestWrapperExecute_IntegrationDryRunDoesNotPersistSpec(t *testing.T) {
	bundle := t.TempDir()
	initial := &Spec{
		Annotations: map[string]string{"beyla.grafana.com/inject": "true"},
		Process: &ProcessSpec{
			Env: []string{"PATH=/usr/bin"},
		},
		Mounts: []MountSpec{},
	}
	if err := SaveSpec(bundle, initial); err != nil {
		t.Fatalf("write initial spec: %v", err)
	}

	cfg := DefaultConfig()
	cfg.DryRun = true
	cfg.SDKPackageVersion = "v0.0.9"
	cfg.HostInstrumentationDir = "/var/lib/beyla/instrumentation"
	cfg.OTLPEndpoint = "http://collector:4318"

	w := NewWrapper(cfg)
	w.run = func(context.Context, string, []string) error { return nil }

	if err := w.Execute(context.Background(), []string{"create", "--bundle", bundle, "test-container"}); err != nil {
		t.Fatalf("execute wrapper: %v", err)
	}

	finalSpec, err := LoadSpec(bundle)
	if err != nil {
		t.Fatalf("read final spec: %v", err)
	}

	env := strings.Join(finalSpec.Process.Env, "\n")
	if strings.Contains(env, "BEYLA_INJECTOR_SDK_PKG_VERSION=") {
		t.Fatalf("dry-run should not persist mutated env vars")
	}
	if len(finalSpec.Mounts) != 0 {
		t.Fatalf("dry-run should not persist injected mounts")
	}
}

func mustContainIntegration(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected to find %q in env set", needle)
	}
}
