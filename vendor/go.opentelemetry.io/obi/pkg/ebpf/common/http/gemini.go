// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// geminiModelPrefix is the URL path segment that precedes the model name
// in both the Gemini Developer API and Vertex AI URL layouts.
const geminiModelPrefix = "/models/"

// geminiHostPattern pairs a known hostname suffix with the URL path segment
// that must be present for the request to be considered a Gemini API call.
type geminiHostPattern struct {
	hostSuffix   string
	requiredPath string
}

// geminiHostPatterns lists known Gemini API hosts and their required path
// segments. The Gemini Developer API uses a simple /models/ prefix, while
// Vertex AI requires the fuller /publishers/google/models/ path to avoid
// matching unrelated Vertex AI prediction endpoints.
var geminiHostPatterns = []geminiHostPattern{
	{"generativelanguage.googleapis.com", "/models/"},
	{"aiplatform.googleapis.com", "/publishers/google/models/"},
}

func isGemini(req *http.Request, respHeader http.Header) bool {
	if respHeader.Get("X-Gemini-Service-Tier") != "" {
		return true
	}

	return isGeminiURL(req)
}

// isGeminiURL checks whether the request targets a known Gemini endpoint
// by matching the hostname against known Gemini/Vertex AI hosts and
// verifying the URL path contains the host-specific model segment.
// This covers the googleapis/go-genai library which calls both the
// Gemini Developer API and Vertex AI backends.
func isGeminiURL(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}

	host := extractHostname(req)
	path := req.URL.Path

	for _, hp := range geminiHostPatterns {
		if strings.HasSuffix(host, hp.hostSuffix) {
			return strings.Contains(path, hp.requiredPath)
		}
	}

	return false
}

// extractHostname returns the hostname from the request, stripping any
// port number that may be present in req.URL.Host or req.Host.
func extractHostname(req *http.Request) string {
	if h := req.URL.Hostname(); h != "" {
		return h
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

type geminiPart struct {
	FunctionCall *struct {
		Name string `json:"name"`
	} `json:"functionCall,omitempty"`
}

func extractGeminiFunctionCalls(resp *request.GeminiResponse) []request.ToolCall {
	var result []request.ToolCall
	for i := range resp.Candidates {
		c := &resp.Candidates[i]
		if c.Content == nil || len(c.Content.Parts) == 0 {
			continue
		}
		var parts []geminiPart
		if err := json.Unmarshal(c.Content.Parts, &parts); err != nil {
			continue
		}
		for j := range parts {
			if parts[j].FunctionCall == nil || parts[j].FunctionCall.Name == "" {
				continue
			}
			result = append(result, request.ToolCall{
				Name: parts[j].FunctionCall.Name,
			})
		}
	}
	return result
}

func GeminiSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isGemini(req, resp.Header) {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("GeminiSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	respB, ok := readHTTPResponseBody("GeminiSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	slog.Debug("Gemini", "request", string(reqB), "response", string(respB))

	var parsedRequest request.GeminiRequest
	if !unmarshalJSON(reqB, &parsedRequest) {
		slog.Debug("failed to parse Gemini request, continuing with partial fields")
	}

	var parsedResponse request.GeminiResponse
	var toolCalls []request.ToolCall

	if looksLikeJSON(respB) {
		if !unmarshalJSON(respB, &parsedResponse) {
			slog.Debug("failed to parse Gemini response, continuing with partial fields")
		}
		toolCalls = extractGeminiFunctionCalls(&parsedResponse)
	} else {
		reader := bytes.NewReader(respB)
		streamResp, streamTools := parseGeminiStream(reader)
		if streamResp != nil {
			parsedResponse = *streamResp
		}
		toolCalls = streamTools
	}

	model := extractGeminiModel(req)
	operation := extractGeminiOperation(req)
	isStream := isGeminiStream(req)

	baseSpan.SubType = request.HTTPSubtypeGemini
	baseSpan.GenAI = &request.GenAI{
		Gemini: &request.VendorGemini{
			Input:     parsedRequest,
			Output:    parsedResponse,
			Model:     model,
			Operation: operation,
			IsStream:  isStream,
			ToolCalls: toolCalls,
		},
	}

	return *baseSpan, true
}

// isGeminiStream detects whether the Gemini call is a streaming request
// by checking if the URL path contains "streamGenerateContent".
func isGeminiStream(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	return strings.Contains(req.URL.Path, "streamGenerateContent")
}

// extractGeminiModel extracts the model name from the URL path.
// Supported patterns:
//   - Gemini API:  /v1beta/models/{model}:generateContent
//   - Vertex AI:   /v1/projects/{p}/locations/{l}/publishers/google/models/{model}:generateContent
func extractGeminiModel(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	path := req.URL.Path
	idx := strings.Index(path, geminiModelPrefix)
	if idx < 0 {
		return ""
	}
	model := path[idx+len(geminiModelPrefix):]
	if colonIdx := strings.Index(model, ":"); colonIdx >= 0 {
		model = model[:colonIdx]
	}
	return model
}

// extractGeminiOperation extracts the operation name from the URL path.
// The operation appears after the colon in the model segment, e.g.
// /models/gemini-2.0-flash:generateContent → generate_content.
func extractGeminiOperation(req *http.Request) string {
	if req == nil || req.URL == nil {
		return request.DefaultGeminiOperation
	}
	path := req.URL.Path
	idx := strings.Index(path, geminiModelPrefix)
	if idx < 0 {
		return request.DefaultGeminiOperation
	}
	after := path[idx+len(geminiModelPrefix):]
	colonIdx := strings.Index(after, ":")
	if colonIdx < 0 || colonIdx+1 >= len(after) {
		return request.DefaultGeminiOperation
	}
	return camelToSnake(after[colonIdx+1:])
}

// camelToSnake converts a camelCase string to snake_case.
func camelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
