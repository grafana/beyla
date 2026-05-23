// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type anthropicContentBlock struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

func extractAnthropicToolCalls(content json.RawMessage) []request.ToolCall {
	if len(content) == 0 {
		return nil
	}

	var blocks []anthropicContentBlock
	if err := json.Unmarshal(content, &blocks); err != nil {
		return nil
	}

	var result []request.ToolCall
	for i := range blocks {
		if blocks[i].Type != "tool_use" || blocks[i].Name == "" {
			continue
		}
		result = append(result, request.ToolCall{
			ID:   blocks[i].ID,
			Name: blocks[i].Name,
		})
	}
	return result
}

func isAnthropic(hdr http.Header) bool {
	isAnthropic := false
	for _, header := range []string{
		"Anthropic-Organization-Id",
		"Anthropic-Ratelimit-Input-Tokens-Remaining",
		"Anthropic-Ratelimit-Output-Tokens-Limit",
		"Anthropic-Ratelimit-Input-Tokens-Limit",
		"Anthropic-Ratelimit-Requests-Limit",
	} {
		if val := hdr.Get(header); val != "" {
			isAnthropic = true
			break
		}
	}

	// we do this extra check because for errors they don't
	// send the usual Anthropic headers
	if !isAnthropic {
		for _, v := range hdr {
			for _, hv := range v {
				if strings.Contains(hv, "api.anthropic.com") {
					isAnthropic = true
					break
				}
			}
		}
	}

	return isAnthropic
}

func AnthropicSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	isAnthropic := isAnthropic(resp.Header)

	if !isAnthropic {
		return *baseSpan, false
	}

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return *baseSpan, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	respB, err := getResponseBody(resp)
	if err != nil && len(respB) == 0 {
		return *baseSpan, false
	}

	slog.Debug("Anthropic", "request", string(reqB), "response", string(respB))

	var parsedRequest request.AnthropicRequest
	if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
		slog.Debug("failed to parse Anthropic request", "error", err)
	}

	var parsedResponse request.AnthropicResponse
	var toolCalls []request.ToolCall
	if len(respB) > 0 && respB[0] == '{' {
		if err := json.Unmarshal(respB, &parsedResponse); err != nil {
			slog.Debug("failed to parse Anthropic response", "error", err)
		}
		toolCalls = extractAnthropicToolCalls(parsedResponse.Content)
	} else {
		reader := bytes.NewReader(respB)
		if streamResponse, tc, err := parseAnthropicStream(reader); err == nil {
			parsedResponse = *streamResponse
			toolCalls = tc
		}
	}

	baseSpan.SubType = request.HTTPSubtypeAnthropic
	baseSpan.GenAI = &request.GenAI{
		Anthropic: &request.VendorAnthropic{
			Input:     parsedRequest,
			Output:    parsedResponse,
			ToolCalls: toolCalls,
		},
	}

	return *baseSpan, true
}

// AnthropicStreamEvent represents different types of streaming events
type AnthropicStreamEvent struct {
	Type string `json:"type"`
}

type MessageStartEvent struct {
	Type    string `json:"type"`
	Message struct {
		Model string `json:"model"`
		ID    string `json:"id"`
		Type  string `json:"type"`
		Role  string `json:"role"`
		Usage struct {
			InputTokens              int `json:"input_tokens"`
			OutputTokens             int `json:"output_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
		} `json:"usage"`
	} `json:"message"`
}

type ContentBlockDelta struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"delta"`
}

type MessageDeltaEvent struct {
	Type  string `json:"type"`
	Delta struct {
		StopReason   string  `json:"stop_reason"`
		StopSequence *string `json:"stop_sequence"`
	} `json:"delta"`
	Usage struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
	} `json:"usage"`
}

// parseAnthropicStream parses the SSE stream from Anthropic API and returns the complete response
func parseAnthropicStream(reader io.Reader) (*request.AnthropicResponse, []request.ToolCall, error) {
	scanner := bufio.NewScanner(reader)
	response := &request.AnthropicResponse{}

	var contentBuilder strings.Builder
	var toolCalls []request.ToolCall
	var currentEvent string
	var currentData string

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines (they separate events)
		if line == "" {
			if currentEvent != "" && currentData != "" {
				if err := processEvent(currentEvent, currentData, response, &contentBuilder, &toolCalls); err != nil {
					return nil, nil, fmt.Errorf("error processing event %s: %w", currentEvent, err)
				}
			}
			currentEvent = ""
			currentData = ""
			continue
		}

		// Parse event line
		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}

		// Parse data line
		if strings.HasPrefix(line, "data: ") {
			currentData = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("error reading stream: %w", err)
	}

	response.Content = json.RawMessage(contentBuilder.String())
	return response, toolCalls, nil
}

func processEvent(eventType, data string, response *request.AnthropicResponse, contentBuilder *strings.Builder, toolCalls *[]request.ToolCall) error {
	switch eventType {
	case "message_start":
		var event MessageStartEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return err
		}
		response.Model = event.Message.Model
		response.ID = event.Message.ID
		response.Role = event.Message.Role
		response.Type = event.Message.Type
		response.Usage.InputTokens += event.Message.Usage.InputTokens
		response.Usage.OutputTokens += event.Message.Usage.OutputTokens
		response.Usage.CacheCreationInputTokens += event.Message.Usage.CacheCreationInputTokens
		response.Usage.CacheReadInputTokens += event.Message.Usage.CacheReadInputTokens

	case "content_block_delta":
		var event ContentBlockDelta
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return err
		}
		if event.Delta.Type == "text_delta" {
			contentBuilder.WriteString(event.Delta.Text)
		}

	case "message_delta":
		var event MessageDeltaEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return err
		}
		response.StopReason = event.Delta.StopReason
		response.StopSequence = event.Delta.StopSequence
		response.Usage.InputTokens += event.Usage.InputTokens
		response.Usage.OutputTokens += event.Usage.OutputTokens
		response.Usage.CacheCreationInputTokens += event.Usage.CacheCreationInputTokens
		response.Usage.CacheReadInputTokens += event.Usage.CacheReadInputTokens

	case "content_block_start":
		var event struct {
			ContentBlock anthropicContentBlock `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return err
		}
		if event.ContentBlock.Type == "tool_use" && event.ContentBlock.Name != "" {
			*toolCalls = append(*toolCalls, request.ToolCall{
				ID:   event.ContentBlock.ID,
				Name: event.ContentBlock.Name,
			})
		}

	case "ping", "content_block_stop", "message_stop":
		return nil

	default:
		return nil
	}

	return nil
}
