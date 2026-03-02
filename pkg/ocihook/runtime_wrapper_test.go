package ocihook

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseBundleArg(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{name: "long option", args: []string{"--bundle", "/tmp/b"}, want: "/tmp/b"},
		{name: "short option", args: []string{"-b", "/tmp/b"}, want: "/tmp/b"},
		{name: "long equals", args: []string{"--bundle=/tmp/b"}, want: "/tmp/b"},
		{name: "short equals", args: []string{"-b=/tmp/b"}, want: "/tmp/b"},
		{name: "none", args: []string{"foo"}, want: ""},
		{name: "missing value", args: []string{"--bundle"}, wantErr: "missing value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBundleArg(tt.args)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected bundle %q, got %q", tt.want, got)
			}
		})
	}
}

func TestWrapperExecute_NoMutationOnNonMutatingCommand(t *testing.T) {
	cfg := DefaultConfig()
	w := NewWrapper(cfg)

	loadCalled := false
	w.loadSpec = func(string) (*Spec, error) {
		loadCalled = true
		return nil, nil
	}

	delegated := false
	w.run = func(context.Context, string, []string) error {
		delegated = true
		return nil
	}

	if err := w.Execute(context.Background(), []string{"delete", "id1"}); err != nil {
		t.Fatalf("unexpected execute error: %v", err)
	}
	if loadCalled {
		t.Fatalf("expected no spec load for non-mutating command")
	}
	if !delegated {
		t.Fatalf("expected delegate execution")
	}
}

func TestWrapperExecute_MutatesAndSavesOnCreate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SDKPackageVersion = "v0.1.0"
	cfg.HostInstrumentationDir = "/var/lib/beyla/instrumentation"

	w := NewWrapper(cfg)
	w.getwd = func() (string, error) { return "/bundle", nil }

	spec := &Spec{Annotations: map[string]string{cfg.Policy.OptInAnnotation: "true"}, Process: &ProcessSpec{Env: []string{}}}
	w.loadSpec = func(string) (*Spec, error) { return spec, nil }

	saved := false
	w.saveSpec = func(string, *Spec) error {
		saved = true
		return nil
	}
	w.run = func(context.Context, string, []string) error { return nil }

	if err := w.Execute(context.Background(), []string{"create", "id1"}); err != nil {
		t.Fatalf("unexpected execute error: %v", err)
	}
	if !saved {
		t.Fatalf("expected mutated spec to be saved")
	}
}

func TestWrapperExecute_PermissiveOnLoadFailure(t *testing.T) {
	cfg := DefaultConfig()
	w := NewWrapper(cfg)
	w.getwd = func() (string, error) { return "/bundle", nil }
	w.loadSpec = func(string) (*Spec, error) { return nil, errors.New("boom") }

	delegated := false
	w.run = func(context.Context, string, []string) error {
		delegated = true
		return nil
	}

	if err := w.Execute(context.Background(), []string{"create", "id1"}); err != nil {
		t.Fatalf("unexpected execute error: %v", err)
	}
	if !delegated {
		t.Fatalf("expected delegate execution in permissive mode")
	}
}

func TestWrapperExecute_StrictOnLoadFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeStrict

	w := NewWrapper(cfg)
	w.getwd = func() (string, error) { return "/bundle", nil }
	w.loadSpec = func(string) (*Spec, error) { return nil, errors.New("boom") }
	w.run = func(context.Context, string, []string) error {
		t.Fatalf("delegate must not be called in strict mode load failure")
		return nil
	}

	err := w.Execute(context.Background(), []string{"create", "id1"})
	if err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Fatalf("expected strict mode error, got %v", err)
	}
}

func TestWrapperExecute_DryRunSkipsSave(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DryRun = true
	cfg.SDKPackageVersion = "v0.1.0"
	cfg.HostInstrumentationDir = "/var/lib/beyla/instrumentation"

	w := NewWrapper(cfg)
	w.getwd = func() (string, error) { return "/bundle", nil }

	spec := &Spec{
		Annotations: map[string]string{cfg.Policy.OptInAnnotation: "true"},
		Process:     &ProcessSpec{Env: []string{}},
	}
	w.loadSpec = func(string) (*Spec, error) { return spec, nil }
	w.saveSpec = func(string, *Spec) error {
		t.Fatalf("save should not be called in dry-run mode")
		return nil
	}

	delegated := false
	w.run = func(context.Context, string, []string) error {
		delegated = true
		return nil
	}

	if err := w.Execute(context.Background(), []string{"create", "id1"}); err != nil {
		t.Fatalf("unexpected execute error: %v", err)
	}
	if !delegated {
		t.Fatalf("expected delegate execution in dry-run mode")
	}
}

func TestWrapperExecute_EmitsDecisionReport(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DecisionReport = "stderr"
	cfg.SDKPackageVersion = "v0.1.0"
	cfg.HostInstrumentationDir = "/var/lib/beyla/instrumentation"

	w := NewWrapper(cfg)
	w.getwd = func() (string, error) { return "/bundle", nil }
	w.loadSpec = func(string) (*Spec, error) {
		return &Spec{
			Annotations: map[string]string{cfg.Policy.OptInAnnotation: "true"},
			Process:     &ProcessSpec{Env: []string{}},
		}, nil
	}
	w.saveSpec = func(string, *Spec) error { return nil }
	w.run = func(context.Context, string, []string) error { return nil }

	reported := false
	w.report = func(c Config, report *DecisionReport) error {
		reported = true
		if c.DecisionReport != "stderr" {
			t.Fatalf("unexpected report target %q", c.DecisionReport)
		}
		if report.Timestamp.IsZero() || report.Timestamp.After(time.Now().Add(time.Second)) {
			t.Fatalf("unexpected report timestamp %v", report.Timestamp)
		}
		if report.Command != "create" {
			t.Fatalf("unexpected command in report: %q", report.Command)
		}
		if !report.PolicyMatched {
			t.Fatalf("expected policy to match in report")
		}
		if !report.Mutated || !report.Saved || !report.Delegated {
			t.Fatalf("expected mutate/save/delegate report flags to be true: %+v", report)
		}
		if report.FinalStatus != "delegated_with_mutation" {
			t.Fatalf("unexpected final status %q", report.FinalStatus)
		}
		return nil
	}

	if err := w.Execute(context.Background(), []string{"create", "id1"}); err != nil {
		t.Fatalf("unexpected execute error: %v", err)
	}
	if !reported {
		t.Fatalf("expected decision report emitter to be called")
	}
}
