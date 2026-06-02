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

func isQwen(respHeader http.Header) bool {
	for _, header := range []string{"X-DashScope-Request-Id", "X-Dashscope-Call-Gateway"} {
		if val := respHeader.Get(header); val != "" {
			return true
		}
	}
	return false
}

func QwenSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isQwen(resp.Header) {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("QwenSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("QwenSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	slog.Debug("Qwen", "request", string(reqB), "response", string(respB))

	parsedRequest := parseOpenAIInput(reqB)
	parsedResponse := parseVendorOpenAI(respB)

	if parsedResponse.ID == "" {
		var responseID struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(respB, &responseID); err == nil {
			parsedResponse.ID = responseID.RequestID
		}
	}

	if parsedResponse.ID == "" {
		// Fall back to response headers when body capture is partial/truncated.
		for _, headerName := range []string{"X-DashScope-Request-Id", "X-Request-Id"} {
			if headerValue := strings.TrimSpace(resp.Header.Get(headerName)); headerValue != "" {
				parsedResponse.ID = headerValue
				break
			}
		}
	}

	parsedResponse.OperationName = extractQwenOperation(req)
	if parsedResponse.ResponseModel == "" {
		parsedResponse.ResponseModel = parsedRequest.Model
	}
	if parsedRequest.Model == "" {
		parsedRequest.Model = parsedResponse.ResponseModel
	}

	parsedResponse.Request = parsedRequest
	parsedResponse.ToolCalls = extractToolCalls(parsedResponse.Choices)

	baseSpan.SubType = request.HTTPSubtypeQwen
	baseSpan.GenAI = &request.GenAI{
		Qwen: &parsedResponse,
	}

	return *baseSpan, true
}

func extractQwenOperation(req *http.Request) string {
	if req == nil {
		return request.GenerationOperationName
	}

	path := requestPath(req)
	switch {
	case strings.Contains(path, "/chat/completions"):
		return request.ChatOperationName
	case strings.Contains(path, "/completions"):
		return request.CompletionOperationName
	case strings.Contains(path, "/embeddings"):
		return request.EmbeddingOperationName
	case strings.Contains(path, "/generation"):
		return request.GenerationOperationName
	default:
		return request.GenerationOperationName
	}
}
