// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"encoding/json"
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
	headerDetected := isQwen(resp.Header)

	// Fast exit: not detected by headers and URL doesn't match
	if !headerDetected && !isQwenCompatibleURL(req) {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("QwenSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	// If not detected by headers, verify model name starts with "qwen"
	if !headerDetected {
		model := extractModelField(reqB)
		if !strings.HasPrefix(strings.ToLower(model), "qwen") {
			return *baseSpan, false
		}
	}

	respB, ok := readHTTPResponseBody("QwenSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	parsedRequest := parseOpenAIInput(reqB)
	parsedResponse, toolCalls := parseOpenAICompatibleResponse(respB)

	// Qwen-specific: try to extract request_id from response body
	if parsedResponse.ID == "" && looksLikeJSON(respB) {
		var responseID struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(respB, &responseID); err == nil {
			parsedResponse.ID = responseID.RequestID
		}
	}

	// Fallback: try to get request ID from response headers
	if parsedResponse.ID == "" {
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
	parsedResponse.ToolCalls = toolCalls

	baseSpan.SubType = request.HTTPSubtypeQwen
	baseSpan.GenAI = &request.GenAI{
		Qwen: parsedResponse,
	}

	return *baseSpan, true
}

// isQwenCompatibleURL checks if the request targets a Qwen/DashScope
// endpoint that serves Qwen models.
func isQwenCompatibleURL(req *http.Request) bool {
	if req == nil {
		return false
	}
	if !isQwenHost(req) {
		return false
	}
	path := requestPath(req)
	return strings.Contains(path, "/chat/completions") ||
		strings.Contains(path, "/completions") ||
		strings.Contains(path, "/embeddings") ||
		strings.Contains(path, "/generation")
}

func isQwenHost(req *http.Request) bool {
	var host string
	if req.URL != nil {
		host = req.URL.Host
	}
	if host == "" {
		host = req.Host
	}
	host = strings.ToLower(host)
	return strings.Contains(host, "dashscope.aliyuncs.com") ||
		strings.Contains(host, "dashscope.aliyun.com")
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
