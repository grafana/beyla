// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"

	jsoniter "github.com/json-iterator/go"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

var jsonBestEffort = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	// modelSearchWindow limits model-field regex to the start of the body so
	// we don't match "model" keys inside user prompts or message content.
	modelSearchWindow = 200
	// responseHeaderSearchWindow limits regex extraction for top-level response
	// fields (id, model, object) so we don't match nested values in payloads.
	responseHeaderSearchWindow = 800
)

var jsonStringFieldRegexpCache sync.Map

func jsonStringFieldRegexp(field string) *regexp.Regexp {
	if cached, ok := jsonStringFieldRegexpCache.Load(field); ok {
		return cached.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`"` + field + `"\s*:\s*"([^"]+)"`)
	actual, _ := jsonStringFieldRegexpCache.LoadOrStore(field, re)
	return actual.(*regexp.Regexp)
}

// extractJSONStringField returns the string value for a top-level JSON field
// using regex. window limits the search range; 0 searches the full body.
func extractJSONStringField(body []byte, field string, window int) string {
	if len(body) == 0 {
		return ""
	}
	search := body
	if window > 0 && len(search) > window {
		search = search[:window]
	}
	if matches := jsonStringFieldRegexp(field).FindSubmatch(search); len(matches) == 2 {
		return strings.TrimSpace(string(matches[1]))
	}
	return ""
}

// extractModelField tries the early body window first, then the full captured
// prefix. Used only when jsoniter could not reach model before truncation.
func extractModelField(body []byte) string {
	if model := extractJSONStringField(body, "model", modelSearchWindow); model != "" {
		return model
	}
	return extractJSONStringField(body, "model", 0)
}

// unmarshalJSONBestEffort unmarshals body into v using json-iterator, which
// populates fields seen before truncation even when the JSON is incomplete.
func unmarshalJSONBestEffort(body []byte, v any) {
	if len(body) == 0 {
		return
	}
	_ = jsonBestEffort.Unmarshal(body, v)
}

func readHTTPRequestBody(component string, req *http.Request, baseSpan *request.Span, emptyLogAttrs ...any) ([]byte, bool) {
	if req == nil || req.Body == nil {
		return nil, true
	}
	body, err := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	if err == nil {
		return body, true
	}
	if len(body) == 0 {
		if len(emptyLogAttrs) > 0 {
			slog.Debug(component+": request body is empty", emptyLogAttrs...)
		}
		return nil, false
	}
	logTruncatedRequestBody(component, err, len(body), req, baseSpan)
	return body, true
}

func readHTTPResponseBody(component string, resp *http.Response, baseSpan *request.Span, emptyLogAttrs ...any) ([]byte, bool) {
	body, err := getResponseBody(resp)
	if err == nil {
		return body, true
	}
	if len(body) == 0 {
		if len(emptyLogAttrs) > 0 {
			slog.Debug(component+": response body is empty", emptyLogAttrs...)
		}
		return nil, false
	}
	logTruncatedResponseBody(component, err, len(body), resp, baseSpan)
	return body, true
}

// readHTTPRequestBodyLenient reads the request body without aborting when the
// read fails with no bytes — used when classification already succeeded.
func readHTTPRequestBodyLenient(component string, req *http.Request, baseSpan *request.Span, logAttrs ...any) []byte {
	if req == nil || req.Body == nil {
		return nil
	}
	body, err := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	if err == nil {
		return body
	}
	if len(body) == 0 {
		logAttrs = append(logAttrs, "error", err)
		slog.Debug(component+": failed to read request body, continuing without it", logAttrs...)
		return nil
	}
	logTruncatedRequestBody(component, err, len(body), req, baseSpan)
	return body
}

// readHTTPResponseBodyLenient reads the response body without aborting when
// the read fails with no bytes.
func readHTTPResponseBodyLenient(component string, resp *http.Response, baseSpan *request.Span, logAttrs ...any) []byte {
	body, err := getResponseBody(resp)
	if err == nil {
		return body
	}
	if len(body) == 0 {
		logAttrs = append(logAttrs, "error", err)
		slog.Debug(component+": failed to read response body, continuing without it", logAttrs...)
		return nil
	}
	logTruncatedResponseBody(component, err, len(body), resp, baseSpan)
	return body
}

func logTruncatedRequestBody(component string, err error, got int, req *http.Request, baseSpan *request.Span) {
	slog.Debug(component+": truncated request body, continuing with partial data",
		"error", err,
		"bytes", got,
		"contentLength", req.ContentLength,
		"spanContentLength", baseSpan.ContentLength,
	)
}

func logTruncatedResponseBody(component string, err error, got int, resp *http.Response, baseSpan *request.Span) {
	slog.Debug(component+": truncated response body, continuing with partial data",
		"error", err,
		"bytes", got,
		"contentLength", resp.ContentLength,
		"spanResponseLength", baseSpan.ResponseLength,
	)
}

func parseOpenAIInput(body []byte) request.OpenAIInput {
	var parsed request.OpenAIInput
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.Model == "" {
		parsed.Model = extractModelField(body)
	}
	return parsed
}

func parseVendorOpenAI(body []byte) request.VendorOpenAI {
	var parsed request.VendorOpenAI
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.ID == "" {
		parsed.ID = extractJSONStringField(body, "id", responseHeaderSearchWindow)
	}
	if parsed.ResponseModel == "" {
		parsed.ResponseModel = extractJSONStringField(body, "model", responseHeaderSearchWindow)
	}
	if parsed.OperationName == "" {
		parsed.OperationName = extractJSONStringField(body, "object", responseHeaderSearchWindow)
	}
	return parsed
}

func parseAnthropicRequest(body []byte) request.AnthropicRequest {
	var parsed request.AnthropicRequest
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.Model == "" {
		parsed.Model = extractModelField(body)
	}
	return parsed
}

func parseAnthropicResponse(body []byte) request.AnthropicResponse {
	var parsed request.AnthropicResponse
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.ID == "" {
		parsed.ID = extractJSONStringField(body, "id", responseHeaderSearchWindow)
	}
	if parsed.Model == "" {
		parsed.Model = extractJSONStringField(body, "model", responseHeaderSearchWindow)
	}
	if parsed.Type == "" {
		parsed.Type = extractJSONStringField(body, "type", responseHeaderSearchWindow)
	}
	return parsed
}

func parseEmbeddingRequest(body []byte) request.EmbeddingRequest {
	var parsed request.EmbeddingRequest
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.Model == "" {
		parsed.Model = extractModelField(body)
	}
	return parsed
}

// unmarshalJSON is a thin wrapper for callers that only need a success flag.
func unmarshalJSON(body []byte, v any) bool {
	if len(body) == 0 {
		return false
	}
	return jsonBestEffort.Unmarshal(body, v) == nil
}
