package ocihook

import "testing"

func TestEvaluatePolicy(t *testing.T) {
	cfg := DefaultConfig()

	t.Run("mutate only create", func(t *testing.T) {
		d := EvaluatePolicy("run", &Spec{Annotations: map[string]string{cfg.Policy.OptInAnnotation: "true"}}, cfg)
		if d.ShouldMutate {
			t.Fatalf("expected mutation to be disabled for command run")
		}
	})

	t.Run("requires opt-in annotation", func(t *testing.T) {
		d := EvaluatePolicy("create", &Spec{Annotations: map[string]string{}}, cfg)
		if d.ShouldMutate {
			t.Fatalf("expected mutation to be disabled without opt-in")
		}
	})

	t.Run("accepts truthy annotation values", func(t *testing.T) {
		d := EvaluatePolicy("create", &Spec{Annotations: map[string]string{cfg.Policy.OptInAnnotation: "yes"}}, cfg)
		if !d.ShouldMutate {
			t.Fatalf("expected mutation to be enabled, reason=%s", d.Reason)
		}
	})

	t.Run("falls back to env var selector", func(t *testing.T) {
		d := EvaluatePolicy("create", &Spec{
			Annotations: map[string]string{},
			Process: &ProcessSpec{
				Env: []string{"PATH=/usr/bin", cfg.Policy.OptInEnvVar + "=true"},
			},
		}, cfg)
		if !d.ShouldMutate {
			t.Fatalf("expected mutation to be enabled from env selector, reason=%s", d.Reason)
		}
	})

	t.Run("supports env-only policy", func(t *testing.T) {
		cfg.Policy.OptInAnnotation = ""
		d := EvaluatePolicy("create", &Spec{
			Process: &ProcessSpec{
				Env: []string{cfg.Policy.OptInEnvVar + "=1"},
			},
		}, cfg)
		if !d.ShouldMutate {
			t.Fatalf("expected mutation to be enabled with env-only policy, reason=%s", d.Reason)
		}
	})
}
