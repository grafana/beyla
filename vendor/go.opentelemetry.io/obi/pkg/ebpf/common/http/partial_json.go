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

	jsoniter "github.com/json-iterator/go"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

var jsonBestEffort = jsoniter.ConfigCompatibleWithStandardLibrary

// looksLikeJSON returns true if the data starts with '{' or '[' after
// stripping leading ASCII whitespace. This avoids misclassifying plain
// JSON responses (which may have leading newlines/spaces) as SSE streams.
func looksLikeJSON(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

const (
	// modelSearchWindow limits extraction for top-level request model
	// fields to the start of the request payload.
	modelSearchWindow = 200
	// responseHeaderSearchWindow limits extraction for top-level response
	// fields (id, model, object) to the start of the response payload.
	responseHeaderSearchWindow = 800
)

// extractJSONStringField returns the string value for a top-level JSON field.
// window limits the search range; 0 searches the full body.
func extractJSONStringField(body []byte, field string, window int) string {
	if len(body) == 0 {
		return ""
	}
	search := body
	if window > 0 && len(search) > window {
		search = search[:window]
	}

	dec := json.NewDecoder(bytes.NewReader(search))
	root, err := dec.Token()
	if err != nil || root != json.Delim('{') {
		return ""
	}

	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return ""
		}
		key, ok := keyToken.(string)
		if !ok {
			return ""
		}

		if key != field {
			if err := skipJSONValue(dec); err != nil {
				return ""
			}
			continue
		}

		value, err := dec.Token()
		if err != nil {
			return ""
		}
		if value, ok := value.(string); ok {
			return strings.TrimSpace(value)
		}
		return ""
	}

	return ""
}

func skipJSONValue(dec *json.Decoder) error {
	value, err := dec.Token()
	if err != nil {
		return err
	}

	delim, ok := value.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		for dec.More() {
			if _, err := dec.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
	default:
		return nil
	}

	_, err = dec.Token()
	return err
}

// extractModelField searches the top-level model field in the captured body.
// Used only when jsoniter could not reach model before truncation.
func extractModelField(body []byte) string {
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
	if len(parsed.Messages) == 0 && len(body) > 0 {
		parsed.Messages = extractJSONRawField(body, "messages")
	}
	return parsed
}

// extractJSONRawField returns the raw value of a top-level field. It works on
// truncated JSON as long as the target field's value is complete in body.
// Returns nil if the body isn't a JSON object, the field is absent, or its
// value is cut off.
func extractJSONRawField(body []byte, field string) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(body))

	// Consume the opening '{'.
	if t, err := dec.Token(); err != nil {
		return nil
	} else if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil
	}

	for dec.More() {
		keyTok, err := dec.Token() // object key
		if err != nil {
			return nil
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil { // exactly one value
			return nil
		}
		if key, _ := keyTok.(string); key == field {
			return raw
		}
	}
	return nil
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
