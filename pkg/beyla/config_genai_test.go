package beyla

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCohereConfigV1(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cohere  string
		enabled bool
		invalid bool
	}{
		{name: "enabled", cohere: "{enabled: true}", enabled: true},
		{name: "disabled", cohere: "{enabled: false}"},
		{name: "unset", cohere: "{}"},
		{name: "invalid flag", cohere: "{enabled: invalid}", invalid: true},
		{name: "invalid section", cohere: "invalid", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := fmt.Sprintf(`
open_port: 8080
trace_printer: text
ebpf:
  payload_extraction:
    http:
      genai:
        openai:
          enabled: true
        cohere: %s
`, tc.cohere)
			cfg, err := LoadConfig(strings.NewReader(data))
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NoError(t, cfg.Validate())
			assert.True(t, cfg.EBPF.PayloadExtraction.HTTP.GenAI.OpenAI.Enabled)
			assert.Equal(t, tc.enabled, cfg.EBPF.PayloadExtraction.HTTP.GenAI.Cohere.Enabled)
			assert.Equal(t, tc.enabled, cfg.AsOBI().EBPF.PayloadExtraction.HTTP.GenAI.Cohere.Enabled)
		})
	}
}
