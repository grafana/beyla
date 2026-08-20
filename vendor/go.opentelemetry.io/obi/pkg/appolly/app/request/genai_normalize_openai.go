// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"encoding/json"
	"strings"
)

type openAIInputAudio struct {
	Data   string `json:"data"`
	Format string `json:"format,omitempty"`
}

type openAIResponsesContentBlock struct {
	Type       string            `json:"type"`
	Text       string            `json:"text,omitempty"`
	Refusal    string            `json:"refusal,omitempty"`
	ImageURL   string            `json:"image_url,omitempty"`
	FileID     string            `json:"file_id,omitempty"`
	FileData   string            `json:"file_data,omitempty"`
	FileURL    string            `json:"file_url,omitempty"`
	Filename   string            `json:"filename,omitempty"`
	InputAudio *openAIInputAudio `json:"input_audio,omitempty"`
}

// normalizeOpenAIMessages converts OpenAI-style messages (flat "content")
// to the semconv parts schema.
func normalizeOpenAIMessages(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var msgs []struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content"`
		ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
		ToolCallID string          `json:"tool_call_id,omitempty"`
	}
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(msgs))
	for _, m := range msgs {
		nm := normalizedMessage{Role: m.Role}
		nm.Parts = openAIContentToParts(m.Content)

		if len(m.ToolCalls) > 0 {
			nm.Parts = append(nm.Parts, openAIToolCallsToParts(m.ToolCalls)...)
		}
		if m.ToolCallID != "" {
			for i := range nm.Parts {
				nm.Parts[i].ID = m.ToolCallID
				nm.Parts[i].Type = "tool_call_response"
				nm.Parts[i].Response = nm.Parts[i].Content
				nm.Parts[i].Content = ""
			}
		}
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// openAIContentToParts converts OpenAI message content (string or
// structured array) to semconv parts. Structured content blocks
// (image_url, input_audio, file, refusal) map to the corresponding
// semconv part types (uri, blob, file, text) per the GenAI semconv
// schema, which requires modality on uri/blob/file parts.
func openAIContentToParts(content json.RawMessage) []normalizedPart {
	if len(content) == 0 {
		return nil
	}

	var s string
	if err := json.Unmarshal(content, &s); err == nil {
		return []normalizedPart{{Type: "text", Content: s}}
	}

	var blocks []struct {
		Type     string `json:"type"`
		Text     string `json:"text,omitempty"`
		Refusal  string `json:"refusal,omitempty"`
		ImageURL *struct {
			URL    string `json:"url"`
			Detail string `json:"detail,omitempty"`
		} `json:"image_url,omitempty"`
		InputAudio *openAIInputAudio `json:"input_audio,omitempty"`
		File       *struct {
			FileID   string `json:"file_id,omitempty"`
			Filename string `json:"filename,omitempty"`
			FileData string `json:"file_data,omitempty"`
		} `json:"file,omitempty"`
	}
	if err := json.Unmarshal(content, &blocks); err != nil {
		return []normalizedPart{{Type: "text", Content: string(content)}}
	}

	parts := make([]normalizedPart, 0, len(blocks))
	for _, b := range blocks {
		switch b.Type {
		case "text":
			parts = append(parts, normalizedPart{Type: "text", Content: b.Text})
		case "image_url":
			if b.ImageURL != nil {
				if part, ok := openAIImageURLPart(b.ImageURL.URL); ok {
					parts = append(parts, part)
				}
			}
		case "input_audio":
			if b.InputAudio != nil {
				parts = append(parts, openAIAudioPart(b.InputAudio))
			}
		case "file":
			if b.File != nil {
				modality := modalityFromFilename(b.File.Filename)
				if b.File.FileID != "" {
					parts = append(parts, normalizedPart{
						Type:     "file",
						FileID:   b.File.FileID,
						Modality: modality,
					})
				} else if b.File.FileData != "" {
					parts = append(parts, openAIFileDataPart(b.File.FileData, modality))
				}
			}
		case "refusal":
			parts = append(parts, normalizedPart{Type: "text", Content: b.Refusal})
		default:
			parts = append(parts, normalizedPart{Type: b.Type, Content: b.Text})
		}
	}
	return parts
}

func openAIResponsesContentToParts(content json.RawMessage) []normalizedPart {
	if len(content) == 0 {
		return nil
	}

	var text string
	if err := json.Unmarshal(content, &text); err == nil {
		return []normalizedPart{{Type: "text", Content: text}}
	}

	var blocks []openAIResponsesContentBlock
	if err := json.Unmarshal(content, &blocks); err != nil {
		return []normalizedPart{{Type: "text", Content: string(content)}}
	}

	parts := make([]normalizedPart, 0, len(blocks))
	for _, block := range blocks {
		if part, ok := openAIResponsesContentBlockToPart(block); ok {
			parts = append(parts, part)
		}
	}
	return parts
}

func openAIResponsesContentBlockToPart(block openAIResponsesContentBlock) (normalizedPart, bool) {
	switch block.Type {
	case "text", "input_text", "output_text":
		return normalizedPart{Type: "text", Content: block.Text}, true
	case "refusal":
		return normalizedPart{Type: "text", Content: block.Refusal}, true
	case "input_image":
		if block.FileID != "" {
			return normalizedPart{
				Type:     "file",
				FileID:   block.FileID,
				Modality: "image",
			}, true
		}
		return openAIImageURLPart(block.ImageURL)
	case "input_file":
		return openAIResponsesFilePart(block)
	case "input_audio":
		if block.InputAudio == nil {
			return normalizedPart{}, false
		}
		return openAIAudioPart(block.InputAudio), true
	default:
		return normalizedPart{Type: block.Type, Content: block.Text}, true
	}
}

func openAIResponsesFilePart(block openAIResponsesContentBlock) (normalizedPart, bool) {
	modalitySource := block.Filename
	if modalitySource == "" {
		modalitySource = block.FileURL
	}
	modality := modalityFromFilename(modalitySource)

	switch {
	case block.FileID != "":
		return normalizedPart{Type: "file", FileID: block.FileID, Modality: modality}, true
	case block.FileURL != "":
		return normalizedPart{Type: "uri", URI: block.FileURL, Modality: modality}, true
	case block.FileData != "":
		return openAIFileDataPart(block.FileData, modality), true
	default:
		return normalizedPart{}, false
	}
}

func openAIFileDataPart(fileData, modality string) normalizedPart {
	part := normalizedPart{
		Type:     "blob",
		Content:  fileData,
		Modality: modality,
	}
	if data, mimeType, ok := openAIBase64DataURL(fileData); ok {
		part.Content = data
		part.MimeType = mimeType
	}
	return part
}

func openAIAudioPart(audio *openAIInputAudio) normalizedPart {
	part := normalizedPart{
		Type:     "blob",
		Content:  audio.Data,
		Modality: "audio",
	}
	if audio.Format != "" {
		part.MimeType = "audio/" + audio.Format
	}
	return part
}

func openAIImageURLPart(imageURL string) (normalizedPart, bool) {
	if imageURL == "" {
		return normalizedPart{}, false
	}

	if data, mimeType, ok := openAIBase64DataURL(imageURL); ok {
		return normalizedPart{
			Type:     "blob",
			Content:  data,
			Modality: "image",
			MimeType: mimeType,
		}, true
	}

	return normalizedPart{
		Type:     "uri",
		URI:      imageURL,
		Modality: "image",
	}, true
}

func openAIBase64DataURL(value string) (data, mimeType string, ok bool) {
	metadata, data, ok := strings.Cut(value, ",")
	if !ok || !strings.HasPrefix(metadata, "data:") || !strings.HasSuffix(metadata, ";base64") {
		return "", "", false
	}

	mimeType = strings.TrimSuffix(strings.TrimPrefix(metadata, "data:"), ";base64")
	return data, mimeType, true
}

// modalityFromFilename returns a semconv modality string derived from a
// filename's extension. Non-media files use the standard document modality.
func modalityFromFilename(filename string) string {
	if filename == "" {
		return "document"
	}
	dot := strings.LastIndex(filename, ".")
	if dot < 0 || dot == len(filename)-1 {
		return "document"
	}
	switch strings.ToLower(filename[dot+1:]) {
	case "png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "tiff":
		return "image"
	case "mp3", "wav", "ogg", "flac", "m4a", "aac", "opus":
		return "audio"
	case "mp4", "webm", "mov", "mkv", "avi":
		return "video"
	}
	return "document"
}

func openAIToolCallsToParts(raw json.RawMessage) []normalizedPart {
	var calls []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil
	}

	parts := make([]normalizedPart, 0, len(calls))
	for _, c := range calls {
		parts = append(parts, normalizedPart{
			Type:      "tool_call",
			ID:        c.ID,
			Name:      c.Function.Name,
			Arguments: c.Function.Arguments,
		})
	}
	return parts
}

// normalizeOpenAIOutput converts OpenAI response choices to semconv output
// messages schema.
func normalizeOpenAIOutput(ai *VendorOpenAI) string {
	if len(ai.Choices) > 0 {
		return normalizeOpenAIChoices(ai.Choices)
	}

	if len(ai.Output) > 0 {
		return normalizeOpenAIResponsesOutput(ai.Output)
	}
	if len(ai.Items) > 0 {
		return string(ai.Items)
	}
	if len(ai.Data) > 0 {
		return string(ai.Data)
	}
	return ""
}

// normalizeOpenAIResponsesOutput converts the OpenAI Responses API output
// array to the semconv output messages schema. The Responses API output is a
// heterogeneous array whose item types include "message", "function_call", and
// others ("reasoning", "web_search_call", ...). Only message and function_call
// items have semconv mappings; unknown item types are dropped.
func normalizeOpenAIResponsesOutput(raw json.RawMessage) string {
	var items []struct {
		Type    string          `json:"type"`
		Role    string          `json:"role"`
		Status  string          `json:"status"`
		Content json.RawMessage `json:"content"`
		// function_call items
		ID        string          `json:"id"`
		CallID    string          `json:"call_id"`
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(items))
	for _, item := range items {
		switch item.Type {
		case "function_call":
			id := item.CallID
			if id == "" {
				id = item.ID
			}
			out = append(out, normalizedMessage{
				Role: "assistant",
				Parts: []normalizedPart{{
					Type:      "tool_call",
					ID:        id,
					Name:      item.Name,
					Arguments: item.Arguments,
				}},
			})
		case "", "message":
			parts := openAIResponsesContentToParts(item.Content)
			if len(parts) == 0 {
				continue
			}
			out = append(out, normalizedMessage{
				Role:         item.Role,
				Parts:        parts,
				FinishReason: item.Status,
			})
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// normalizeOpenAIResponsesInput converts the OpenAI Responses API `input`
// array to the semconv input messages schema. The array is heterogeneous:
// "message" items carry conversation turns, "function_call" items carry the
// model's tool calls, and "function_call_output" items carry the tool results
// sent back to the model. Preserving all three keeps output-only stateful
// continuations (previous_response_id / Conversation) visible in
// gen_ai.input.messages. Unknown item types are dropped.
func normalizeOpenAIResponsesInput(raw json.RawMessage) string {
	var items []struct {
		Type      string          `json:"type"`
		Role      string          `json:"role"`
		Content   json.RawMessage `json:"content"`
		CallID    string          `json:"call_id"`
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Output    json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(items))
	for i := range items {
		item := &items[i]
		switch item.Type {
		case "function_call":
			out = append(out, normalizedMessage{
				Role: "assistant",
				Parts: []normalizedPart{{
					Type:      "tool_call",
					ID:        item.CallID,
					Name:      item.Name,
					Arguments: item.Arguments,
				}},
			})
		case "function_call_output":
			var resp any
			if len(item.Output) > 0 {
				_ = json.Unmarshal(item.Output, &resp)
			}
			out = append(out, normalizedMessage{
				Role: "tool",
				Parts: []normalizedPart{{
					Type:     "tool_call_response",
					ID:       item.CallID,
					Response: resp,
				}},
			})
		case "", "message":
			parts := openAIResponsesContentToParts(item.Content)
			if len(parts) == 0 {
				continue
			}
			out = append(out, normalizedMessage{Role: item.Role, Parts: parts})
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

func normalizeOpenAIChoices(raw json.RawMessage) string {
	var choices []struct {
		Message struct {
			Role      string          `json:"role"`
			Content   json.RawMessage `json:"content"`
			ToolCalls json.RawMessage `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}
	if err := json.Unmarshal(raw, &choices); err != nil {
		return string(raw)
	}

	out := make([]normalizedMessage, 0, len(choices))
	for _, c := range choices {
		nm := normalizedMessage{
			Role:         c.Message.Role,
			FinishReason: c.FinishReason,
		}
		nm.Parts = openAIContentToParts(c.Message.Content)
		if len(c.Message.ToolCalls) > 0 {
			nm.Parts = append(nm.Parts, openAIToolCallsToParts(c.Message.ToolCalls)...)
		}
		out = append(out, nm)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return string(raw)
	}
	return string(b)
}
