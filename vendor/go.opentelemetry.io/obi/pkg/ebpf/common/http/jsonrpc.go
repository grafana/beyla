// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   *jsonRPCError   `json:"error"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	jsonRPCVersion     = "2.0"
	jsonRPCContentType = "application/json-rpc"
)

func JSONRPCSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req.Method != http.MethodPost {
		return *baseSpan, false
	}

	// Fast path: check Content-Type header. Media types are case-insensitive
	// and may include parameters (e.g. "; charset=utf-8"), so parse with mime.
	detected := false
	if ct := req.Header.Get("Content-Type"); ct != "" {
		if mediaType, _, err := mime.ParseMediaType(ct); err == nil {
			detected = mediaType == jsonRPCContentType
		}
	}

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return *baseSpan, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	rpcReq, err := parseJSONRPCRequest(reqB, detected)
	if err != nil {
		return *baseSpan, false
	}

	version := rpcReq.JSONRPC
	if version == "" && detected {
		version = jsonRPCVersion
	}

	result := &request.JSONRPC{
		Method:  rpcReq.Method,
		Version: version,
	}

	if len(rpcReq.ID) > 0 && string(rpcReq.ID) != "null" {
		result.RequestID = rawIDString(rpcReq.ID)
	}

	// Parse response for error information
	if resp != nil && resp.Body != nil {
		respB, err := getResponseBody(resp)
		if err == nil {
			parseJSONRPCResponse(respB, result)
		}
	}

	baseSpan.SubType = request.HTTPSubtypeJSONRPC
	baseSpan.JSONRPC = result

	return *baseSpan, true
}

// rawIDString returns a json.RawMessage ID as a plain string, stripping JSON quotes from string IDs.
func rawIDString(id json.RawMessage) string {
	var s string
	if json.Unmarshal(id, &s) == nil {
		return s
	}
	return string(id)
}

// parseJSONRPCRequest tries to parse the body as a JSON-RPC request.
// Returns the first request and any error.
// TODO: for batch requests, emit a span per request instead of only the first.
func parseJSONRPCRequest(data []byte, headerDetected bool) (jsonRPCRequest, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return jsonRPCRequest{}, errors.New("empty body")
	}

	// Try single request first (most common case)
	if data[0] == '{' {
		var req jsonRPCRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return jsonRPCRequest{}, fmt.Errorf("invalid JSON: %w", err)
		}
		if !isValidJSONRPCVersion(req.JSONRPC, headerDetected) {
			return jsonRPCRequest{}, errors.New("not a JSON-RPC request")
		}
		if req.Method == "" {
			return jsonRPCRequest{}, errors.New("missing method field")
		}
		return req, nil
	}

	// Try batch request — currently only extracts the first request.
	if data[0] == '[' {
		var batch []jsonRPCRequest
		if err := json.Unmarshal(data, &batch); err != nil {
			return jsonRPCRequest{}, fmt.Errorf("invalid JSON batch: %w", err)
		}
		if len(batch) == 0 {
			return jsonRPCRequest{}, errors.New("empty batch")
		}
		first := batch[0]
		if !isValidJSONRPCVersion(first.JSONRPC, headerDetected) {
			return jsonRPCRequest{}, errors.New("not a JSON-RPC batch")
		}
		if first.Method == "" {
			return jsonRPCRequest{}, errors.New("missing method field in batch")
		}
		return first, nil
	}

	return jsonRPCRequest{}, errors.New("unexpected JSON token")
}

func isValidJSONRPCVersion(version string, headerDetected bool) bool {
	if version == jsonRPCVersion {
		return true
	}
	// Allow empty only when the header was the detection signal.
	return version == "" && headerDetected
}

func parseJSONRPCResponse(data []byte, result *request.JSONRPC) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return
	}

	switch data[0] {
	case '{':
		var resp jsonRPCResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return
		}
		applyRPCError(resp, result)
	case '[':
		var batch []jsonRPCResponse
		if err := json.Unmarshal(data, &batch); err != nil {
			return
		}
		if resp, ok := matchResponse(batch, result.RequestID); ok {
			applyRPCError(resp, result)
		}
	}
}

// matchResponse finds the response matching the given request ID.
func matchResponse(batch []jsonRPCResponse, requestID string) (jsonRPCResponse, bool) {
	if requestID == "" {
		return jsonRPCResponse{}, false
	}
	for _, resp := range batch {
		if rawIDString(resp.ID) == requestID {
			return resp, true
		}
	}
	return jsonRPCResponse{}, false
}

func applyRPCError(resp jsonRPCResponse, result *request.JSONRPC) {
	if resp.Error != nil {
		result.ErrorCode = resp.Error.Code
		result.ErrorMessage = resp.Error.Message
	}
}
