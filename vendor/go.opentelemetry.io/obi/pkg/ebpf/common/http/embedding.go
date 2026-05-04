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

// embeddingHostPattern pairs a known hostname suffix with a required URL path
// suffix and the provider name to assign when matched.
type embeddingHostPattern struct {
	hostSuffix string
	pathSuffix string
	provider   string
}

// embeddingHostPatterns lists known embedding API hosts and their required
// URL path suffixes. Matching is performed by hostname suffix and path suffix,
// which naturally handles arbitrary path prefixes before the API suffix.
var embeddingHostPatterns = []embeddingHostPattern{
	{"api.voyageai.com", "/v1/embeddings", "voyage"},
	{"api.cohere.com", "/v2/embed", "cohere"},
	{"api.jina.ai", "/v1/embeddings", "jina"},
}

// parseEmbeddingProvider checks whether the request targets a known embedding-only
// provider by matching the hostname and URL path against embeddingHostPatterns.
// Returns the provider name if matched, or empty string otherwise.
func parseEmbeddingProvider(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}

	host := extractHostname(req)
	path := strings.TrimSuffix(req.URL.Path, "/")

	for _, hp := range embeddingHostPatterns {
		if (host == hp.hostSuffix || strings.HasSuffix(host, "."+hp.hostSuffix)) &&
			strings.HasSuffix(path, hp.pathSuffix) {
			return hp.provider
		}
	}

	return ""
}

// EmbeddingSpan detects embedding API calls to Voyage AI, Cohere, and Jina AI
// based on hostname and URL path matching, and extracts embedding-specific
// fields into the span.
func EmbeddingSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	provider := parseEmbeddingProvider(req)
	if provider == "" {
		return *baseSpan, false
	}

	// Request body parsing is best-effort: since the provider is already
	// confirmed by hostname+path, a body read failure should not prevent
	// classification — otherwise the request falls through to downstream
	// detectors and may be misclassified.
	var reqB []byte
	if req.Body != nil {
		var err error
		reqB, err = io.ReadAll(req.Body)
		if err != nil {
			slog.Debug("EmbeddingSpan: failed to read request body, continuing without it", "provider", provider, "error", err)
		}
		req.Body = io.NopCloser(bytes.NewBuffer(reqB))
	}

	// Response body parsing is best-effort: truncated responses may fail
	// to parse but should not prevent provider detection.
	respB, err := getResponseBody(resp)
	if err != nil {
		slog.Debug("EmbeddingSpan: failed to read response body, continuing without it", "provider", provider, "error", err)
	}

	slog.Debug("Embedding", "provider", provider, "request", string(reqB), "response", string(respB))

	var parsedRequest request.EmbeddingRequest
	if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
		slog.Debug("failed to parse embedding request", "provider", provider, "error", err)
	}

	var parsedResponse request.EmbeddingResponse
	if len(respB) > 0 {
		if err := json.Unmarshal(respB, &parsedResponse); err != nil {
			slog.Debug("failed to parse embedding response", "provider", provider, "error", err)
		}
	}

	baseSpan.SubType = request.HTTPSubtypeEmbedding
	baseSpan.GenAI = &request.GenAI{
		Embedding: &request.VendorEmbedding{
			Provider: provider,
			Model:    parsedRequest.Model,
			Input:    parsedRequest,
			Output:   parsedResponse,
		},
	}

	return *baseSpan, true
}
