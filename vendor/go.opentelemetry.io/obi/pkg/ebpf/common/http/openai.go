// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
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

func OpenAISpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	// Check any of the well known response headers that OpenAI would use
	isOpenAI := false
	for _, header := range []string{"Openai-Version", "Openai-Organization", "Openai-Project", "Openai-Processing-Ms"} {
		if val := resp.Header.Get(header); val != "" {
			isOpenAI = true
			break
		}
	}

	if !isOpenAI {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("OpenAISpan", req, baseSpan, "headers", resp.Header)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("OpenAISpan", resp, baseSpan, "headers", resp.Header)
	if !ok {
		return *baseSpan, false
	}

	slog.Debug("OpenAI", "request", string(reqB), "response", string(respB))

	parsedRequest := parseOpenAIInput(reqB)
	parsedResponse := parseVendorOpenAI(respB)

	if parsedResponse.ResponseModel == "" {
		parsedResponse.ResponseModel = parsedRequest.Model
	}
	if parsedRequest.Model == "" {
		parsedRequest.Model = parsedResponse.ResponseModel
	}

	parsedResponse.Request = parsedRequest
	parsedResponse.ToolCalls = extractToolCalls(parsedResponse.Choices)

	// Override operation name and derive API type from URL path.
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
			parsedResponse.APIType = "responses"
		}
	}

	baseSpan.SubType = request.HTTPSubtypeOpenAI
	baseSpan.GenAI = &request.GenAI{
		OpenAI: &parsedResponse,
	}

	return *baseSpan, true
}
