// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// rerankProviders maps hostname suffixes to GenAI provider names.
// Provider names are aligned with existing canonical names used elsewhere
// in the codebase (e.g. embedding uses "voyage" for Voyage AI).
var rerankProviders = []struct {
	hostSuffix string
	provider   string
}{
	{"cohere.com", "cohere"},
	{"cohere.ai", "cohere"},
	{"jina.ai", "jina"},
	{"voyageai.com", "voyage"},
	{"dashscope.aliyuncs.com", "qwen"},
	{"dashscope.aliyun.com", "qwen"},
}

// isRerankPath returns true when the request URL path contains a complete
// path segment "rerank" (e.g. /v1/rerank, /v2/rerank).
// Uses path segment matching to avoid false positives on paths where
// "rerank" is just a substring (e.g. /v1/rerankings, /foo/rerankable).
func isRerankPath(req *http.Request) bool {
	path := requestPath(req)
	if path == "" {
		return false
	}

	for _, segment := range strings.Split(path, "/") {
		if segment == "rerank" {
			return true
		}
	}

	return false
}

// rerankProviderFromHost returns the provider name based on the request
// hostname.  It falls back to "unknown" when no known provider matches.
// Uses suffix matching (like EmbeddingSpan) to avoid false positives.
func rerankProviderFromHost(req *http.Request) string {
	host := extractHostname(req)
	for _, p := range rerankProviders {
		if host == p.hostSuffix || strings.HasSuffix(host, "."+p.hostSuffix) {
			return p.provider
		}
	}
	return "unknown"
}

// extractModelFromPartialJSON attempts to extract the top-level model field
// from potentially truncated JSON. This is a fallback when standard
// json.Unmarshal fails due to eBPF buffer truncation.
func extractModelFromPartialJSON(data []byte) string {
	return extractJSONStringField(data, "model", modelSearchWindow)
}

// hasTopLevelRerankSignals uses a streaming JSON decoder to check for
// top-level rerank-specific fields in the request body prefix.  For unknown
// providers, we require "model" plus at least one of "query" or "documents"
// as top-level keys to confirm this is a genuine GenAI rerank request.
//
// Unlike regex-based matching, this approach only inspects top-level object
// keys, so nested JSON like {"workflow": {"model": ..., "query": ...}} will
// not produce false positives.  Truncated bodies are handled gracefully:
// the decoder stops on error and we use whatever top-level keys were found.
func hasTopLevelRerankSignals(data []byte) bool {
	window := data
	if len(window) > modelSearchWindow {
		window = window[:modelSearchWindow]
	}

	dec := json.NewDecoder(bytes.NewReader(window))

	// Expect opening '{' for a top-level JSON object.
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return false
	}

	var hasModel, hasQuery, hasDocuments bool

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			break
		}

		key, ok := keyTok.(string)
		if !ok {
			break
		}

		switch key {
		case "model":
			hasModel = true
		case "query":
			hasQuery = true
		case "documents":
			hasDocuments = true
		}

		// Skip the value associated with this key.
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			// Truncated body: stop here and use only the top-level keys found so far.
			break
		}
	}

	return hasModel && (hasQuery || hasDocuments)
}

// RerankSpan detects rerank API calls by URL path matching and validates
// the request against known GenAI providers or request body characteristics.
// The span is classified as rerank only when:
//   - The URL path contains a /rerank segment AND
//   - The hostname matches a known provider OR the request body contains
//     multiple rerank-specific structural signals (model + query/documents)
//
// Body parsing is best-effort: once validated, the span is always classified
// as rerank regardless of body read/parse failures.
func RerankSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isRerankPath(req) {
		return *baseSpan, false
	}

	provider := rerankProviderFromHost(req)

	// Request body parsing is best-effort: read the body first to validate
	// that this is actually a GenAI rerank request (not just any URL ending
	// in /rerank).
	var reqB []byte
	if req.Body != nil {
		var err error
		reqB, err = io.ReadAll(req.Body)
		if err != nil {
			slog.Debug("RerankSpan: failed to read request body, continuing without it", "provider", provider, "error", err)
		}
		req.Body = io.NopCloser(bytes.NewBuffer(reqB))
	}

	// Validate: require either a known provider (by hostname) or top-level
	// rerank-specific fields (model + query/documents) in the request body.
	// This prevents false positives on non-GenAI POST /rerank endpoints
	// where nested keys would otherwise trigger a match.
	if provider == "unknown" && !hasTopLevelRerankSignals(reqB) {
		slog.Debug("RerankSpan: path matches /rerank but no known provider or sufficient structural signals found, skipping", "path", requestPath(req), "host", extractHostname(req))
		return *baseSpan, false
	}

	// At this point, we've confirmed this is a genuine rerank request.
	// Continue with full parsing even if provider is "unknown" (as long as model exists).

	// Response body parsing is best-effort: truncated responses may fail
	// to parse but should not prevent provider detection.
	respB, err := getResponseBody(resp)
	if err != nil {
		slog.Debug("RerankSpan: failed to read response body, continuing without it", "provider", provider, "error", err)
	}

	slog.Debug("Rerank", "provider", provider, "request", string(reqB), "response", string(respB))

	var parsedRequest request.RerankRequest
	if len(reqB) > 0 {
		if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
			slog.Debug("failed to parse rerank request", "provider", provider, "error", err)
			// Fallback: extract model from potentially truncated JSON.
			if parsedRequest.Model == "" {
				parsedRequest.Model = extractModelFromPartialJSON(reqB)
			}
		}
	}

	var parsedResponse request.RerankResponse
	if len(respB) > 0 {
		if err := json.Unmarshal(respB, &parsedResponse); err != nil {
			slog.Debug("failed to parse rerank response", "provider", provider, "error", err)
		}
	}

	baseSpan.SubType = request.HTTPSubtypeRerank
	baseSpan.GenAI = &request.GenAI{
		Rerank: &request.VendorRerank{
			Input:    parsedRequest,
			Output:   parsedResponse,
			Provider: provider,
		},
	}

	return *baseSpan, true
}
