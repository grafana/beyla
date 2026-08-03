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

func looksLikeAnthropicBody(reqB, respB []byte) bool {
	if extractJSONRawField(reqB, "anthropic_version") != nil {
		return false
	}

	// Response: a message object, or an SSE stream beginning with message_start.
	if extractJSONStringField(respB, "type", responseHeaderSearchWindow) == "message" {
		return true
	}
	if bytes.Contains(respB, []byte("message_start")) {
		return true
	}

	// Request: a Claude model with a messages array.
	return strings.HasPrefix(strings.ToLower(extractModelField(reqB)), "claude") &&
		extractJSONRawField(reqB, "messages") != nil
}

func AnthropicSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	isAnthropic := isAnthropic(resp.Header)
	maybeAnthropic := false

	if !isAnthropic {
		if !isHTTP2Request(req) || !strings.HasPrefix(baseSpan.Path, "/v1/messages") {
			return *baseSpan, false
		}
		maybeAnthropic = true
	}

	reqB, ok := readHTTPRequestBody("AnthropicSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("AnthropicSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	if maybeAnthropic {
		if !looksLikeAnthropicBody(reqB, respB) {
			return *baseSpan, false
		}
	}

	slog.Debug("Anthropic", "request", string(reqB), "response", string(respB))

	parsedRequest := parseAnthropicRequest(reqB)

	var parsedResponse request.AnthropicResponse
	var toolCalls []request.ToolCall
	if looksLikeJSON(respB) {
		parsedResponse = parseAnthropicResponse(respB)
		toolCalls = extractAnthropicToolCalls(parsedResponse.Content)
	} else {
		reader := bytes.NewReader(respB)
		streamResponse, tc, err := parseAnthropicStream(reader)
		if err != nil {
			slog.Debug("failed to parse complete Anthropic stream, continuing with partial fields", "error", err)
		}
		if streamResponse != nil {
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
}

// parseAnthropicStream parses the SSE stream from Anthropic API and returns the complete response
func parseAnthropicStream(reader io.Reader) (*request.AnthropicResponse, []request.ToolCall, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)
	response := &request.AnthropicResponse{}

	var contentBuilder strings.Builder
	var toolCalls []request.ToolCall
	var currentEvent string
	var currentData string
	flushEvent := func() {
		eventType, data := currentEvent, currentData
		currentEvent = ""
		currentData = ""
		if eventType == "" || data == "" {
			return
		}
		processEvent(eventType, data, response, &contentBuilder, &toolCalls)
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines (they separate events)
		if line == "" {
			flushEvent()
			continue
		}

		// Parse event line
		if strings.HasPrefix(line, "event:") {
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}

		// Parse data line
		if data, ok := extractSSEData(line); ok {
			currentData = strings.TrimSpace(data)
			continue
		}
	}

	flushEvent()

	response.Content = json.RawMessage(contentBuilder.String())
	if err := scanner.Err(); err != nil {
		return response, toolCalls, fmt.Errorf("error reading stream: %w", err)
	}
	return response, toolCalls, nil
}

func processEvent(eventType, data string, response *request.AnthropicResponse, contentBuilder *strings.Builder, toolCalls *[]request.ToolCall) {
	switch eventType {
	case "message_start":
		var event MessageStartEvent
		unmarshalJSONBestEffort([]byte(data), &event)
		response.Model = event.Message.Model
		response.ID = event.Message.ID
		response.Role = event.Message.Role
		response.Type = event.Message.Type
		var usage request.AnthropicUsage
		if unmarshalJSONContainerBestEffort([]byte(data), &usage, "message", "usage") {
			response.Usage.Merge(usage)
		}

	case "content_block_delta":
		var event ContentBlockDelta
		unmarshalJSONBestEffort([]byte(data), &event)
		if event.Delta.Type == "text_delta" {
			contentBuilder.WriteString(event.Delta.Text)
		}

	case "message_delta":
		var event MessageDeltaEvent
		unmarshalJSONBestEffort([]byte(data), &event)
		response.StopReason = event.Delta.StopReason
		response.StopSequence = event.Delta.StopSequence
		var usage request.AnthropicUsage
		if unmarshalJSONContainerBestEffort([]byte(data), &usage, "usage") {
			response.Usage.Merge(usage)
		}

	case "content_block_start":
		var event struct {
			ContentBlock anthropicContentBlock `json:"content_block"`
		}
		unmarshalJSONBestEffort([]byte(data), &event)
		if event.ContentBlock.Type == "tool_use" && event.ContentBlock.Name != "" {
			*toolCalls = append(*toolCalls, request.ToolCall{
				ID:   event.ContentBlock.ID,
				Name: event.ContentBlock.Name,
			})
		}

	case "ping", "content_block_stop", "message_stop":
		return

	default:
		return
	}
}
