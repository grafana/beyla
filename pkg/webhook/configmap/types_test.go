package configmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
)

func TestRuleConfigSkips(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
		want bool
	}{
		{name: "unset mode defaults to install", mode: "", want: false},
		{name: "explicit install", mode: ModeInstall, want: false},
		{name: "skip", mode: ModeSkip, want: true},
		{name: "unrecognized value defaults to install", mode: Mode("bogus"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RuleConfig{Mode: tt.mode}.Skips())
		})
	}
}

// An unset Mode must be omitted from the marshalled config (omitempty) so the
// shared schema stays backward-compatible with readers that predate the field.
func TestRuleConfigModeOmittedWhenUnset(t *testing.T) {
	out, err := yaml.Marshal(RuleConfig{})
	require.NoError(t, err)
	assert.NotContains(t, string(out), "mode")
}

func TestRuleConfigModeRoundTrip(t *testing.T) {
	in := InjectConfig{
		Rules: []Rule{
			{Selector: K8sSelector{Namespaces: nil}, Config: RuleConfig{Mode: ModeSkip}},
			{Selector: K8sSelector{Namespaces: nil}, Config: RuleConfig{Mode: ModeInstall}},
		},
	}
	out, err := yaml.Marshal(in)
	require.NoError(t, err)
	assert.Contains(t, string(out), "mode: skip")
	assert.Contains(t, string(out), "mode: install")

	var got InjectConfig
	require.NoError(t, yaml.Unmarshal(out, &got))
	require.Len(t, got.Rules, 2)
	assert.True(t, got.Rules[0].Config.Skips())
	assert.False(t, got.Rules[1].Config.Skips())
}

// corev1.EnvVar carries only json tags, which yaml.v3 ignores; the EnvVars
// wrapper bridges through encoding/json so unset optional fields (notably the
// valueFrom pointer) are omitted instead of serialized as `valuefrom: null`,
// and field names follow k8s camelCase conventions. Both a plain value var and
// a valueFrom.secretKeyRef var must survive the round trip intact.
func TestEnvVarsRoundTrip(t *testing.T) {
	in := InjectConfig{
		Rules: []Rule{{
			Config: RuleConfig{
				Env: EnvVars{
					{Name: "OTEL_LOGS_EXPORTER", Value: "none"},
					{Name: "API_KEY", ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "creds"},
							Key:                  "api-key",
						},
					}},
				},
			},
		}},
	}

	out, err := yaml.Marshal(in)
	require.NoError(t, err)
	s := string(out)

	// The unset pointer is dropped, not emitted as null, and the source nests
	// using k8s camelCase keys.
	assert.NotContains(t, s, "valuefrom")
	assert.NotContains(t, s, "valueFrom: null")
	assert.Contains(t, s, "value: none")
	assert.Contains(t, s, "valueFrom:")
	assert.Contains(t, s, "secretKeyRef:")

	var got InjectConfig
	require.NoError(t, yaml.Unmarshal(out, &got))
	require.Len(t, got.Rules, 1)
	assert.Equal(t, in.Rules[0].Config.Env, got.Rules[0].Config.Env)
}

func TestRuleConfigHash(t *testing.T) {
	pastValues := map[uint64]struct{}{}
	rc := RuleConfig{
		Mode: ModeInstall,
		Env:  EnvVars{{Name: "OTEL_LOGS_EXPORTER", Value: "none"}, {Name: "API_KEY", Value: "api-key"}},
	}
	testHashChanged := func(t *testing.T) {
		h := rc.Hash()
		assert.NotContains(t, pastValues, h)
		pastValues[h] = struct{}{}
	}

	h := rc.Hash()
	assert.NotZero(t, h)
	pastValues[h] = struct{}{}
	// multiple calls returns always the same value
	assert.Equal(t, h, rc.Hash())
	assert.Equal(t, h, rc.Hash())
	assert.Equal(t, h, rc.Hash())

	// Changing the order of the env vars does not affect the hash result
	rc.Env = EnvVars{{Name: "API_KEY", Value: "api-key"}, {Name: "OTEL_LOGS_EXPORTER", Value: "none"}}
	assert.Equal(t, h, rc.Hash())

	// Changing the mode affects the hash result
	rc.Mode = ModeSkip
	testHashChanged(t)

	// Adding an env var changes the hash result
	rc.Env = append(rc.Env, corev1.EnvVar{Name: "OTEL_ENDPOINT", ValueFrom: &corev1.EnvVarSource{
		FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "spec.nodeName"},
	}})

	testHashChanged(t)

	// removing an env var changes the hash result
	rc.Env = rc.Env[1:]
	testHashChanged(t)

	// Changing a variable name changes the hash result
	rc.Env[0].Name = "OTEL_SAMPLER"
	testHashChanged(t)

	// Changing a variable value changes the hash result
	rc.Env[0].Value = "always_on"
	testHashChanged(t)

	// Changing ValueFrom changes the hash result
	rc.Env[1].ValueFrom = &corev1.EnvVarSource{
		ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "creds"},
		},
	}
	testHashChanged(t)

	// Ditto
	rc.Env[1].ValueFrom = &corev1.EnvVarSource{}
	testHashChanged(t)
}
