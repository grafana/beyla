// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"encoding/json"
)

// geminiPart captures all Gemini part types including function calls/responses.
type geminiPart struct {
	Text             string          `json:"text,omitempty"`
	FunctionCall     *geminiFuncCall `json:"functionCall,omitempty"`
	FunctionResponse *geminiFuncResp `json:"functionResponse,omitempty"`
}

type geminiFuncCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

type geminiFuncResp struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response,omitempty"`
}

func geminiPartToNormalized(p geminiPart) normalizedPart {
	if p.FunctionCall != nil {
		return normalizedPart{
			Type:      "tool_call",
			Name:      p.FunctionCall.Name,
			Arguments: p.FunctionCall.Args,
		}
	}
	if p.FunctionResponse != nil {
		var resp any
		if len(p.FunctionResponse.Response) > 0 {
			_ = json.Unmarshal(p.FunctionResponse.Response, &resp)
		}
		return normalizedPart{
			Type:     "tool_call_response",
			Name:     p.FunctionResponse.Name,
			Response: resp,
		}
	}
	return normalizedPart{Type: "text", Content: p.Text}
}

// normalizeGeminiInput converts Gemini contents to the semconv schema.
func normalizeGeminiInput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var contents []struct {
		Role  string       `json:"role"`
		Parts []geminiPart `json:"parts"`
	}
	if err := json.Unmarshal(raw, &contents); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(contents))
	for _, c := range contents {
		nm := normalizedMessage{Role: c.Role}
		for _, p := range c.Parts {
			nm.Parts = append(nm.Parts, geminiPartToNormalized(p))
		}
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// normalizeGeminiOutput converts Gemini candidates to semconv output messages.
func normalizeGeminiOutput(resp *GeminiResponse) string {
	if len(resp.Candidates) == 0 {
		return ""
	}

	out := make([]normalizedMessage, 0, len(resp.Candidates))
	for _, c := range resp.Candidates {
		nm := normalizedMessage{FinishReason: c.FinishReason}
		if c.Content != nil {
			nm.Role = c.Content.Role

			var parts []geminiPart
			if err := json.Unmarshal(c.Content.Parts, &parts); err == nil {
				for _, p := range parts {
					nm.Parts = append(nm.Parts, geminiPartToNormalized(p))
				}
			}
		}
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

// normalizeGeminiParts converts Gemini-style parts from a single
// content block to semconv parts.
func normalizeGeminiParts(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var parts []geminiPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return string(raw)
	}

	out := make([]normalizedPart, 0, len(parts))
	for _, p := range parts {
		out = append(out, geminiPartToNormalized(p))
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}
