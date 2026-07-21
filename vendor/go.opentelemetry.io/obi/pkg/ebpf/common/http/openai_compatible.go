// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

func OpenAICompatibleSpan(baseSpan *request.Span, req *http.Request, resp *http.Response, gateways []config.OpenAICompatibleGateway) (request.Span, bool) {
	var reqHost string
	if req.URL != nil {
		reqHost = req.URL.Host
	}
	if reqHost == "" {
		reqHost = req.Host
	}

	hostOnly := reqHost
	port := 0
	if h, p, err := net.SplitHostPort(reqHost); err == nil {
		hostOnly = h
		if pInt, err := strconv.Atoi(p); err == nil {
			port = pInt
		}
	}

	var matchedGateway *config.OpenAICompatibleGateway
	for i := range gateways {
		gw := &gateways[i]
		if !strings.EqualFold(hostOnly, gw.Host) {
			continue
		}
		if gw.Port > 0 && port > 0 && gw.Port != port {
			continue
		}
		matchedGateway = gw
		break
	}

	if matchedGateway == nil {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("OpenAICompatibleSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("OpenAICompatibleSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	parsedRequest := parseOpenAIInput(reqB)
	parsedResponse, toolCalls := parseOpenAICompatibleResponse(respB)

	if parsedResponse.ResponseModel == "" && len(parsedResponse.Choices) == 0 &&
		parsedResponse.Usage.TotalTokens == 0 && len(parsedResponse.Data) == 0 &&
		len(parsedResponse.Output) == 0 && parsedRequest.Model == "" {
		return *baseSpan, false
	}

	if parsedResponse.ResponseModel == "" {
		parsedResponse.ResponseModel = parsedRequest.Model
	}
	if parsedRequest.Model == "" {
		parsedRequest.Model = parsedResponse.ResponseModel
	}

	parsedResponse.Request = parsedRequest
	parsedResponse.ToolCalls = toolCalls

	// Use strings.Contains instead of exact path matching to support
	// gateways mounted under a path prefix (e.g. /litellm/v1/chat/completions).
	if req.URL != nil {
		switch {
		case strings.Contains(req.URL.Path, "/v1/chat/completions"):
			parsedResponse.OperationName = request.ChatOperationName
			parsedResponse.APIType = "chat_completions"
		case strings.Contains(req.URL.Path, "/v1/completions"):
			parsedResponse.OperationName = request.CompletionOperationName
			parsedResponse.APIType = "text_completions"
		case strings.Contains(req.URL.Path, "/v1/embeddings"):
			parsedResponse.OperationName = request.EmbeddingOperationName
			parsedResponse.APIType = "embeddings"
		case strings.Contains(req.URL.Path, "/v1/responses"):
			parsedResponse.APIType = "responses"
		}
	}

	parsedResponse.ProviderName = matchedGateway.Provider
	baseSpan.SubType = request.HTTPSubtypeOpenAICompatible
	baseSpan.GenAI = &request.GenAI{
		OpenAICompatible: parsedResponse,
	}

	return *baseSpan, true
}
