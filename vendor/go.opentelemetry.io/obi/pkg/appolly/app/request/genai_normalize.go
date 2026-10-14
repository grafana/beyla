// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"encoding/json"
)

// Semconv-compliant message types per:
// https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/gen-ai-input-messages.json
// https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/gen-ai-output-messages.json

type normalizedPart struct {
	Type      string          `json:"type"`
	Content   string          `json:"content,omitempty"`
	Response  any             `json:"result,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	URI       string          `json:"uri,omitempty"`
	FileID    string          `json:"file_id,omitempty"`
	Modality  string          `json:"modality,omitempty"`
	MimeType  string          `json:"mime_type,omitempty"`
}

type normalizedMessage struct {
	Role         string           `json:"role"`
	Parts        []normalizedPart `json:"parts"`
	FinishReason string           `json:"finish_reason,omitempty"`
}

func wrapTextAsInputMessage(text string) string {
	msg := normalizedMessage{
		Role:  "user",
		Parts: []normalizedPart{{Type: "text", Content: text}},
	}
	b, err := json.Marshal([]normalizedMessage{msg})
	if err != nil {
		return text
	}
	return string(b)
}

func wrapTextAsOutputMessage(role, text, finishReason string) string {
	msg := normalizedMessage{
		Role:         role,
		Parts:        []normalizedPart{{Type: "text", Content: text}},
		FinishReason: finishReason,
	}
	b, err := json.Marshal([]normalizedMessage{msg})
	if err != nil {
		return text
	}
	return string(b)
}

// NormalizeSystemInstructions converts a plain text system instruction
// to the semconv JSON schema: [{"type":"text","content":"..."}]
func NormalizeSystemInstructions(text string) string {
	if text == "" {
		return ""
	}
	parts := []normalizedPart{{Type: "text", Content: text}}
	b, err := json.Marshal(parts)
	if err != nil {
		return text
	}
	return string(b)
}

type normalizedTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// NormalizeToolDefinitions converts provider-native tool definitions to the
// semconv schema: [{"type":"function","name":"...","description":"...","parameters":{}}]
func NormalizeToolDefinitions(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return string(raw)
	}

	out := make([]normalizedTool, 0, len(items))
	for _, item := range items {
		out = append(out, normalizeToolItem(item)...)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

func normalizeToolItem(raw json.RawMessage) []normalizedTool {
	var probe struct {
		// OpenAI wrapper: {"type":"function","function":{...}}
		Type     string `json:"type"`
		Function *struct {
			Name        string          `json:"name"`
			Description string          `json:"description,omitempty"`
			Parameters  json.RawMessage `json:"parameters,omitempty"`
		} `json:"function,omitempty"`
		// Anthropic direct: {"name":"...","description":"...","input_schema":{}}
		Name        string          `json:"name,omitempty"`
		Description string          `json:"description,omitempty"`
		InputSchema json.RawMessage `json:"input_schema,omitempty"`
		// Gemini: {"functionDeclarations":[{"name":"..."}]}
		FunctionDeclarations []struct {
			Name        string          `json:"name"`
			Description string          `json:"description,omitempty"`
			Parameters  json.RawMessage `json:"parameters,omitempty"`
		} `json:"functionDeclarations,omitempty"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil
	}

	if len(probe.FunctionDeclarations) > 0 {
		out := make([]normalizedTool, 0, len(probe.FunctionDeclarations))
		for _, fd := range probe.FunctionDeclarations {
			if fd.Name == "" {
				continue
			}
			out = append(out, normalizedTool{
				Type:        "function",
				Name:        fd.Name,
				Description: fd.Description,
				Parameters:  fd.Parameters,
			})
		}
		return out
	}

	// OpenAI wrapper: only normalize when the wrapper declares type:"function"
	// and carries a function object. Other wrapper types are not in semconv.
	if probe.Function != nil && probe.Function.Name != "" && (probe.Type == "" || probe.Type == "function") {
		return []normalizedTool{{
			Type:        "function",
			Name:        probe.Function.Name,
			Description: probe.Function.Description,
			Parameters:  probe.Function.Parameters,
		}}
	}

	// Anthropic direct shape. Only emit when a name is present; non-function
	// Anthropic tools (computer_*, text_editor_*, bash_*) carry a type field
	// but are not part of semconv's gen_ai.tool.definitions schema, so drop them.
	if probe.Name != "" && probe.Type == "" {
		return []normalizedTool{{
			Type:        "function",
			Name:        probe.Name,
			Description: probe.Description,
			Parameters:  probe.InputSchema,
		}}
	}

	return nil
}
