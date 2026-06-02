// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func isBedrock(respHeader http.Header, req *http.Request) bool {
	// X-Amzn-Bedrock-Input-Token-Count is always present in successful Bedrock InvokeModel responses.
	if respHeader.Get("X-Amzn-Bedrock-Input-Token-Count") != "" {
		return true
	}
	// For error responses the token-count headers may be absent.
	// Fall back to checking the request host for the Bedrock runtime endpoint.
	if req != nil {
		host := req.Host
		if host == "" && req.URL != nil {
			host = req.URL.Host
		}
		if strings.Contains(host, "bedrock-runtime") && strings.Contains(host, ".amazonaws.com") {
			return true
		}
	}
	return false
}

func BedrockSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isBedrock(resp.Header, req) {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("BedrockSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("BedrockSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	slog.Debug("Bedrock", "request", string(reqB), "response", string(respB))

	var parsedRequest request.BedrockRequest
	if len(reqB) > 0 && !unmarshalJSON(reqB, &parsedRequest) {
		slog.Debug("failed to parse Bedrock request, continuing with partial fields")
	}

	var parsedResponse request.BedrockResponse
	if len(respB) > 0 && !unmarshalJSON(respB, &parsedResponse) {
		slog.Debug("failed to parse Bedrock response, continuing with partial fields")
	}

	// Token counts are reliably present in response headers for successful calls.
	parsedResponse.InputTokens, _ = strconv.Atoi(resp.Header.Get("X-Amzn-Bedrock-Input-Token-Count"))
	parsedResponse.OutputTokens, _ = strconv.Atoi(resp.Header.Get("X-Amzn-Bedrock-Output-Token-Count"))

	model := extractBedrockModel(req)
	isStream := isBedrockStream(req)
	guardrailID := extractBedrockGuardrailID(req, resp)

	baseSpan.SubType = request.HTTPSubtypeAWSBedrock
	baseSpan.GenAI = &request.GenAI{
		Bedrock: &request.VendorBedrock{
			Input:       parsedRequest,
			Output:      parsedResponse,
			Model:       model,
			IsStream:    isStream,
			GuardrailID: guardrailID,
		},
	}

	return *baseSpan, true
}

// extractBedrockModel extracts the model ID from the Bedrock API URL path.
// Bedrock URLs follow the pattern: /model/{modelId}/invoke
func extractBedrockModel(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	path := req.URL.Path
	const prefix = "/model/"
	idx := strings.Index(path, prefix)
	if idx < 0 {
		return ""
	}
	remainder := path[idx+len(prefix):]
	slashIdx := strings.Index(remainder, "/")
	if slashIdx < 0 {
		return remainder
	}
	return remainder[:slashIdx]
}

// isBedrockStream detects streaming Bedrock calls by checking the URL path
// for the invoke-with-response-stream suffix.
func isBedrockStream(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	return strings.Contains(req.URL.Path, "invoke-with-response-stream")
}

// extractBedrockGuardrailID extracts the guardrail identifier from the
// response header or the request URL path.
func extractBedrockGuardrailID(req *http.Request, resp *http.Response) string {
	if id := resp.Header.Get("X-Amzn-Bedrock-Guardrail-Id"); id != "" {
		return id
	}

	if req != nil && req.URL != nil {
		path := req.URL.Path
		const prefix = "/guardrail/"
		if idx := strings.Index(path, prefix); idx >= 0 {
			remainder := path[idx+len(prefix):]
			if slashIdx := strings.Index(remainder, "/"); slashIdx >= 0 {
				return remainder[:slashIdx]
			}
			return remainder
		}
	}

	return ""
}
