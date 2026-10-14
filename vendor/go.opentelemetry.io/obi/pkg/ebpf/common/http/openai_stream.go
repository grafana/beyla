// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// maxStreamToolCalls caps the tool-call accumulator to prevent unbounded
// growth from untrusted tool_calls[].index values.
const maxStreamToolCalls = 256

type openAIStreamChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role      string                 `json:"role"`
			Content   string                 `json:"content"`
			ToolCalls []openAIStreamToolCall `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

type openAIStreamToolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// parseOpenAIStream parses the SSE stream from OpenAI-compatible APIs (including Qwen/DashScope)
// and returns the aggregated response with usage statistics and tool calls.
func parseOpenAIStream(reader io.Reader) (*request.VendorOpenAI, []request.ToolCall) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)
	response := &request.VendorOpenAI{}

	var finishReason string
	var role string
	var contentBuilder strings.Builder
	// toolCallAccum accumulates tool call fragments by index.
	type toolCallAccum struct {
		id   string
		name string
	}
	var accumulators []toolCallAccum

	for scanner.Scan() {
		line := scanner.Text()

		data, ok := extractSSEData(line)
		if !ok {
			continue
		}

		if data == "[DONE]" {
			break
		}

		var chunk openAIStreamChunk
		unmarshalJSONBestEffort([]byte(data), &chunk)
		var responseFields struct {
			ID    string `json:"id"`
			Model string `json:"model"`
		}
		if unmarshalJSONContainerBestEffort([]byte(data), &responseFields, "response") {
			if chunk.ID == "" {
				chunk.ID = responseFields.ID
			}
			if chunk.Model == "" {
				chunk.Model = responseFields.Model
			}
		}
		var usage request.OpenAIUsage
		if unmarshalJSONContainerBestEffort([]byte(data), &usage, "response", "usage") {
			response.Usage.Merge(usage)
		}
		if unmarshalJSONContainerBestEffort([]byte(data), &usage, "usage") {
			response.Usage.Merge(usage)
		}

		// Extract model and id from the first chunk that has them.
		if response.ID == "" && chunk.ID != "" {
			response.ID = chunk.ID
		}
		if response.ResponseModel == "" && chunk.Model != "" {
			response.ResponseModel = chunk.Model
		}

		// Process choices.
		for i := range chunk.Choices {
			choice := &chunk.Choices[i]

			// Track finish reason from the last choice that reports one.
			if choice.FinishReason != nil && *choice.FinishReason != "" {
				finishReason = *choice.FinishReason
			}

			// Capture assistant role (typically in the first delta) and
			// accumulate content fragments to reconstruct the full message.
			if choice.Delta.Role != "" {
				role = choice.Delta.Role
			}
			if choice.Delta.Content != "" {
				contentBuilder.WriteString(choice.Delta.Content)
			}

			// Accumulate tool calls by index.
			for j := range choice.Delta.ToolCalls {
				tc := &choice.Delta.ToolCalls[j]
				idx := tc.Index
				if idx < 0 || idx >= maxStreamToolCalls {
					continue
				}

				// Grow the accumulator slice as needed.
				for len(accumulators) <= idx {
					accumulators = append(accumulators, toolCallAccum{})
				}

				if tc.ID != "" {
					accumulators[idx].id = tc.ID
				}
				if tc.Function.Name != "" {
					accumulators[idx].name = tc.Function.Name
				}

			}
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Debug("parseOpenAIStream: scanner error", "error", err)
	}

	// Build the Choices JSON with the aggregated message content and
	// finish_reason so that VendorOpenAI.GetFinishReasons() and the GenAI
	// output normalization (normalizeOpenAIChoices) work correctly.
	if finishReason != "" || contentBuilder.Len() > 0 {
		type streamChoice struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		}

		sc := streamChoice{FinishReason: finishReason}
		sc.Message.Role = role
		if sc.Message.Role == "" {
			sc.Message.Role = "assistant"
		}
		sc.Message.Content = contentBuilder.String()

		choicesJSON, err := json.Marshal([]streamChoice{sc})
		if err == nil {
			response.Choices = choicesJSON
		}
	}

	// Build the final tool calls list.
	var toolCalls []request.ToolCall
	for i := range accumulators {
		if accumulators[i].name == "" {
			continue
		}
		toolCalls = append(toolCalls, request.ToolCall{
			ID:   accumulators[i].id,
			Name: accumulators[i].name,
		})
	}

	_, inputReported := response.Usage.InputTokenCount()
	_, outputReported := response.Usage.OutputTokenCount()
	if !inputReported && !outputReported && response.ID != "" {
		slog.Debug("parseOpenAIStream: no usage data found in SSE stream, token counts will be 0",
			"id", response.ID, "model", response.ResponseModel, "finishReason", finishReason)
	}

	return response, toolCalls
}
