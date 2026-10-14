// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"encoding/json"
)

// NormalizeBedrockOutput converts Bedrock Claude-style content blocks
// to the semconv output messages schema. For Bedrock responses that use
// Anthropic Claude format, the content blocks are identical to Anthropic.
func NormalizeBedrockOutput(resp *BedrockResponse) string {
	if len(resp.Content) == 0 {
		return ""
	}

	var blocks []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text,omitempty"`
		ID    string          `json:"id,omitempty"`
		Name  string          `json:"name,omitempty"`
		Input json.RawMessage `json:"input,omitempty"`
	}
	if err := json.Unmarshal(resp.Content, &blocks); err != nil {
		return wrapTextAsOutputMessage("assistant", string(resp.Content), resp.StopReason)
	}

	var parts []normalizedPart
	for _, b := range blocks {
		switch b.Type {
		case "text":
			parts = append(parts, normalizedPart{Type: "text", Content: b.Text})
		case "tool_use":
			parts = append(parts, normalizedPart{
				Type:      "tool_call",
				ID:        b.ID,
				Name:      b.Name,
				Arguments: b.Input,
			})
		default:
			parts = append(parts, normalizedPart{Type: b.Type, Content: b.Text})
		}
	}

	msg := normalizedMessage{
		Role:         "assistant",
		Parts:        parts,
		FinishReason: resp.StopReason,
	}

	out, err := json.Marshal([]normalizedMessage{msg})
	if err != nil {
		return string(resp.Content)
	}
	return string(out)
}
