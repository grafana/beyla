// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"encoding/json"
)

// NormalizeAnthropicInput converts Anthropic request messages to semconv
// schema. Anthropic content blocks can contain tool_use and tool_result
// entries that require separate handling from OpenAI format.
func NormalizeAnthropicInput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var msgs []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(msgs))
	for _, m := range msgs {
		nm := normalizedMessage{Role: m.Role}
		nm.Parts = anthropicContentToParts(m.Content)
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

func anthropicContentToParts(content json.RawMessage) []normalizedPart {
	if len(content) == 0 {
		return nil
	}

	var s string
	if err := json.Unmarshal(content, &s); err == nil {
		return []normalizedPart{{Type: "text", Content: s}}
	}

	var blocks []struct {
		Type      string          `json:"type"`
		Text      string          `json:"text,omitempty"`
		ID        string          `json:"id,omitempty"`
		Name      string          `json:"name,omitempty"`
		Input     json.RawMessage `json:"input,omitempty"`
		ToolUseID string          `json:"tool_use_id,omitempty"`
		Content   json.RawMessage `json:"content,omitempty"`
		Thinking  string          `json:"thinking,omitempty"`
	}
	if err := json.Unmarshal(content, &blocks); err != nil {
		return []normalizedPart{{Type: "text", Content: string(content)}}
	}

	parts := make([]normalizedPart, 0, len(blocks))
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
		case "tool_result":
			parts = append(parts, normalizedPart{
				Type:     "tool_call_response",
				ID:       b.ToolUseID,
				Response: extractToolResultContent(b.Content),
			})
		case "thinking":
			parts = append(parts, normalizedPart{Type: "reasoning", Content: b.Thinking})
		default:
			parts = append(parts, normalizedPart{Type: b.Type, Content: b.Text})
		}
	}
	return parts
}

// extractToolResultContent returns the tool result content as a string.
// Anthropic tool_result content can be a string or an array of content blocks.
func extractToolResultContent(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}

	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}

	var obj any
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj
	}

	return string(raw)
}

// NormalizeAnthropicOutput converts Anthropic response content blocks
// to semconv output messages schema.
func NormalizeAnthropicOutput(resp *AnthropicResponse) string {
	if len(resp.Content) == 0 {
		return ""
	}

	var blocks []struct {
		Type     string          `json:"type"`
		Text     string          `json:"text,omitempty"`
		ID       string          `json:"id,omitempty"`
		Name     string          `json:"name,omitempty"`
		Input    json.RawMessage `json:"input,omitempty"`
		Thinking string          `json:"thinking,omitempty"`
	}
	if err := json.Unmarshal(resp.Content, &blocks); err != nil {
		return wrapTextAsOutputMessage(resp.Role, string(resp.Content), resp.StopReason)
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
		case "thinking":
			parts = append(parts, normalizedPart{Type: "reasoning", Content: b.Thinking})
		default:
			parts = append(parts, normalizedPart{Type: b.Type, Content: b.Text})
		}
	}

	msg := normalizedMessage{
		Role:         resp.Role,
		Parts:        parts,
		FinishReason: resp.StopReason,
	}

	out, err := json.Marshal([]normalizedMessage{msg})
	if err != nil {
		return string(resp.Content)
	}
	return string(out)
}
