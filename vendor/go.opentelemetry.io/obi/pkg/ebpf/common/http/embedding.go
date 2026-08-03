// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

	reqB := readHTTPRequestBodyLenient("EmbeddingSpan", req, baseSpan, "provider", provider)
	respB := readHTTPResponseBodyLenient("EmbeddingSpan", resp, baseSpan, "provider", provider)

	slog.Debug("Embedding", "provider", provider, "request", string(reqB), "response", string(respB))

	parsedRequest := parseEmbeddingRequest(reqB)

	var parsedResponse request.EmbeddingResponse
	if len(respB) > 0 && !unmarshalJSON(respB, &parsedResponse) {
		slog.Debug("failed to parse embedding response", "provider", provider)
	}
	var usage request.EmbeddingUsage
	if unmarshalJSONContainerBestEffort(respB, &usage, "usage") {
		parsedResponse.Usage.PromptTokens.Merge(usage.PromptTokens)
		parsedResponse.Usage.TotalTokens.Merge(usage.TotalTokens)
	}
	var billedUnits request.CohereBilledUnits
	if unmarshalJSONContainerBestEffort(respB, &billedUnits, "meta", "billed_units") {
		if parsedResponse.Meta == nil {
			parsedResponse.Meta = &request.CohereResponseMeta{}
		}
		if parsedResponse.Meta.BilledUnits == nil {
			parsedResponse.Meta.BilledUnits = &request.CohereBilledUnits{}
		}
		parsedResponse.Meta.BilledUnits.InputTokens.Merge(billedUnits.InputTokens)
	}
	if parsedResponse.Dimensions == 0 {
		parsedResponse.Dimensions = parseEmbeddingDimensions(&parsedRequest, respB)
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

// parseEmbeddingDimensions returns the dimension count of the first output
// vector in a raw embedding response body, decoded according to the
// representation requested in req. Bodies are parsed best-effort so a batch
// truncated by the capture limit still yields its first complete vector.
func parseEmbeddingDimensions(req *request.EmbeddingRequest, body []byte) int {
	if len(body) == 0 {
		return 0
	}

	dtype := req.RequestedDtype()

	// OpenAI-style layout: {"data":[{"embedding":<vector>}]}
	var openAIStyle struct {
		Data []struct {
			Embedding json.RawMessage `json:"embedding"`
		} `json:"data"`
	}
	unmarshalJSONBestEffort(body, &openAIStyle)
	if len(openAIStyle.Data) > 0 {
		if n := embeddingVectorDims(openAIStyle.Data[0].Embedding, dtype); n > 0 {
			return n
		}
	}

	// Cohere v2 layout: {"embeddings":{"float":[[...]],"binary":[[...]]}}
	var cohereStyle struct {
		Embeddings map[string]json.RawMessage `json:"embeddings"`
	}
	unmarshalJSONBestEffort(body, &cohereStyle)

	return cohereEmbeddingDimensions(cohereStyle.Embeddings)
}

// binaryPackedDims is the number of model dimensions packed into each byte
// entry of a binary/ubinary embedding vector.
const binaryPackedDims = 8

// float32Bytes is the byte width of one float32 embedding element.
const float32Bytes = 4

// cohereEmbeddingDimensions derives the dimension count from Cohere v2
// embeddings keyed by type, preferring non-packed types whose entry count
// equals the dimension count.
func cohereEmbeddingDimensions(embeddings map[string]json.RawMessage) int {
	for _, key := range []string{"float", "int8", "uint8"} {
		if n := cohereVectorDims(embeddings, key); n > 0 {
			return n
		}
	}

	for _, key := range []string{"binary", "ubinary"} {
		if n := cohereVectorDims(embeddings, key); n > 0 {
			return n
		}
	}

	return cohereVectorDims(embeddings, "base64")
}

// cohereVectorDims returns the dimension count derived from the first vector
// under the given embedding type key.
func cohereVectorDims(embeddings map[string]json.RawMessage, key string) int {
	raw, ok := embeddings[key]
	if !ok {
		return 0
	}

	var vectors []json.RawMessage
	if !unmarshalJSON(raw, &vectors) || len(vectors) == 0 {
		return 0
	}

	return embeddingVectorDims(vectors[0], key)
}

// embeddingVectorDims returns the dimension count of a single vector, honoring
// the requested element representation. A partially captured vector fails
// strict decoding and yields 0.
func embeddingVectorDims(vec json.RawMessage, dtype string) int {
	trimmed := bytes.TrimSpace(vec)
	if len(trimmed) == 0 {
		return 0
	}

	switch trimmed[0] {
	case '[':
		var arr []json.Number
		if json.Unmarshal(trimmed, &arr) != nil || len(arr) == 0 {
			return 0
		}
		if isPackedDtype(dtype) {
			return len(arr) * binaryPackedDims
		}
		return len(arr)
	case '"':
		var s string
		if json.Unmarshal(trimmed, &s) != nil || s == "" {
			return 0
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(decoded) == 0 {
			return 0
		}
		return dimsFromPackedBytes(len(decoded), dtype)
	}

	return 0
}

func isPackedDtype(dtype string) bool {
	return dtype == "binary" || dtype == "ubinary"
}

// dimsFromPackedBytes converts a decoded base64 byte count into a dimension
// count based on the element representation.
func dimsFromPackedBytes(n int, dtype string) int {
	switch {
	case dtype == "int8" || dtype == "uint8":
		return n
	case isPackedDtype(dtype):
		return n * binaryPackedDims
	default:
		if n%float32Bytes != 0 {
			return 0
		}
		return n / float32Bytes
	}
}
