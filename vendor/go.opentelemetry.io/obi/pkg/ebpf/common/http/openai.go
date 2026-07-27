// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

func extractToolCalls(choices json.RawMessage) []request.ToolCall {
	if len(choices) == 0 {
		return nil
	}

	var parsed []struct {
		Message struct {
			ToolCalls []openAIToolCall `json:"tool_calls"`
		} `json:"message"`
	}
	if err := json.Unmarshal(choices, &parsed); err != nil {
		return nil
	}

	var result []request.ToolCall
	for i := range parsed {
		for j := range parsed[i].Message.ToolCalls {
			tc := &parsed[i].Message.ToolCalls[j]
			if tc.Function.Name == "" {
				continue
			}
			result = append(result, request.ToolCall{
				ID:   tc.ID,
				Name: tc.Function.Name,
			})
		}
	}
	return result
}

// parseOpenAICompatibleResponse parses an OpenAI-compatible response body,
// handling both JSON and SSE streaming formats. It returns the parsed response
// and any tool calls extracted from the response.
func parseOpenAICompatibleResponse(respB []byte) (*request.VendorOpenAI, []request.ToolCall) {
	if looksLikeJSON(respB) {
		resp := parseVendorOpenAI(respB)
		return &resp, extractToolCalls(resp.Choices)
	}
	reader := bytes.NewReader(respB)
	return parseOpenAIStream(reader)
}

func looksLikeOpenAIBody(reqB, respB []byte, path string) bool {
	model := strings.ToLower(genaiModel(reqB, respB))

	// "gpt" covers chat/completions and responses; "text-embedding" covers the
	// embeddings.
	return strings.HasPrefix(model, "gpt") || (strings.HasPrefix(model, "text-embedding") && strings.Contains(path, "/v1/embeddings"))
}

func OpenAISpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	// Check any of the well known response headers that OpenAI would use
	isOpenAI := false
	for _, header := range []string{"Openai-Version", "Openai-Organization", "Openai-Project", "Openai-Processing-Ms"} {
		if val := resp.Header.Get(header); val != "" {
			isOpenAI = true
			break
		}
	}

	maybeOpenAI := false

	if !isOpenAI {
		// HTTP/2 requests carry no usable headers, so fall back to a body-shape
		// heuristic. OpenAI is the catch-all for OpenAI-compatible payloads that
		// no sibling provider (Qwen, Anthropic) claims.
		if !isHTTP2Request(req) || !strings.Contains(baseSpan.Path, "/v1/") {
			return *baseSpan, false
		}
		maybeOpenAI = true
	}

	reqB, ok := readHTTPRequestBody("OpenAISpan", req, baseSpan, "headers", resp.Header)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("OpenAISpan", resp, baseSpan, "headers", resp.Header)
	if !ok {
		return *baseSpan, false
	}

	if maybeOpenAI {
		if !looksLikeOpenAIBody(reqB, respB, baseSpan.Path) {
			return *baseSpan, false
		}
	}

	slog.Debug("OpenAI", "request", string(reqB), "response", string(respB))

	parsedRequest := parseOpenAIInput(reqB)
	parsedResponse, toolCalls := parseOpenAICompatibleResponse(respB)

	if parsedResponse.ResponseModel == "" {
		parsedResponse.ResponseModel = parsedRequest.Model
	}
	if parsedRequest.Model == "" {
		parsedRequest.Model = parsedResponse.ResponseModel
	}

	parsedResponse.Request = parsedRequest
	parsedResponse.ToolCalls = toolCalls

	// Override operation name and derive API type from URL path. The path is
	// authoritative even when the response carries no `object` field (error
	// responses don't): the operation name feeds required metric attributes
	// (gen_ai.client.operation.duration / token.usage), so failed calls must
	// carry it too.
	if req.URL != nil {
		path := strings.TrimSuffix(req.URL.Path, "/")
		switch path {
		case "/v1/chat/completions":
			parsedResponse.OperationName = request.ChatOperationName
			parsedResponse.APIType = "chat_completions"
		case "/v1/embeddings":
			parsedResponse.OperationName = request.EmbeddingOperationName
			parsedResponse.APIType = "embeddings"
		case "/v1/responses":
			parsedResponse.OperationName = request.ResponseOperationName
			parsedResponse.APIType = "responses"
		case "/v1/conversations":
			parsedResponse.OperationName = request.ConversationOperationName
		}
	}

	baseSpan.SubType = request.HTTPSubtypeOpenAI
	baseSpan.GenAI = &request.GenAI{
		OpenAI: parsedResponse,
	}

	return *baseSpan, true
}
