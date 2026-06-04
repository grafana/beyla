package configmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
