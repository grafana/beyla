// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"io"
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

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return *baseSpan, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	respB, err := getResponseBody(resp)
	if err != nil && len(respB) == 0 {
		return *baseSpan, false
	}

	slog.Debug("Bedrock", "request", string(reqB), "response", string(respB))

	var parsedRequest request.BedrockRequest
	if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
		slog.Debug("failed to parse Bedrock request", "error", err)
	}

	var parsedResponse request.BedrockResponse
	if len(respB) > 0 {
		if err := json.Unmarshal(respB, &parsedResponse); err != nil {
			slog.Debug("failed to parse Bedrock response", "error", err)
		}
	}

	// Token counts are reliably present in response headers for successful calls.
	parsedResponse.InputTokens, _ = strconv.Atoi(resp.Header.Get("X-Amzn-Bedrock-Input-Token-Count"))
	parsedResponse.OutputTokens, _ = strconv.Atoi(resp.Header.Get("X-Amzn-Bedrock-Output-Token-Count"))

	model := extractBedrockModel(req)

	baseSpan.SubType = request.HTTPSubtypeAWSBedrock
	baseSpan.GenAI = &request.GenAI{
		Bedrock: &request.VendorBedrock{
			Input:  parsedRequest,
			Output: parsedResponse,
			Model:  model,
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
