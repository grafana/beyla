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

func looksLikeBedrockBody(reqB []byte) bool {
	return strings.HasPrefix(extractJSONStringField(reqB, "anthropic_version", 0), "bedrock")
}

func BedrockSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	maybeBedrock := false
	if !isBedrock(resp.Header, req) {
		if !isHTTP2Request(req) || !strings.Contains(baseSpan.Path, "/model/") {
			return *baseSpan, false
		}
		maybeBedrock = true
	}

	reqB, ok := readHTTPRequestBody("BedrockSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	if maybeBedrock {
		if !looksLikeBedrockBody(reqB) {
			return *baseSpan, false
		}
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
	var usage request.BedrockUsage
	if unmarshalJSONContainerBestEffort(respB, &usage, "usage") {
		mergeBedrockUsage(&parsedResponse.Usage, usage)
	}
	parsedResponse.PromptTokenCount.Merge(tokenCountJSONField(respB, "prompt_token_count"))
	parsedResponse.GenerationTokenCount.Merge(tokenCountJSONField(respB, "generation_token_count"))

	// Token counts are reliably present in response headers for successful calls.
	_ = json.Unmarshal([]byte(resp.Header.Get("X-Amzn-Bedrock-Input-Token-Count")), &parsedResponse.InputTokens)
	_ = json.Unmarshal([]byte(resp.Header.Get("X-Amzn-Bedrock-Output-Token-Count")), &parsedResponse.OutputTokens)

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

func mergeBedrockUsage(dst *request.BedrockUsage, src request.BedrockUsage) {
	dst.InputTokens.Merge(src.InputTokens)
	dst.OutputTokens.Merge(src.OutputTokens)
	dst.TotalTokens.Merge(src.TotalTokens)
	dst.CacheReadInputTokens.Merge(src.CacheReadInputTokens)
	dst.CacheWriteInputTokens.Merge(src.CacheWriteInputTokens)
	if src.CacheDetails != nil {
		dst.CacheDetails = src.CacheDetails
	}
	if src.CacheCreation != nil {
		if dst.CacheCreation == nil {
			dst.CacheCreation = &request.AnthropicCacheCreation{}
		}
		dst.CacheCreation.Ephemeral5mInputTokens.Merge(src.CacheCreation.Ephemeral5mInputTokens)
		dst.CacheCreation.Ephemeral1hInputTokens.Merge(src.CacheCreation.Ephemeral1hInputTokens)
	}
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
