// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// mcpMethods enumerates known MCP JSON-RPC method names.
var mcpMethods = map[string]struct{}{
	"initialize":                         {},
	"notifications/initialized":          {},
	"tools/call":                         {},
	"tools/list":                         {},
	"resources/read":                     {},
	"resources/list":                     {},
	"resources/subscribe":                {},
	"resources/unsubscribe":              {},
	"resources/templates/list":           {},
	"prompts/get":                        {},
	"prompts/list":                       {},
	"completion/complete":                {},
	"logging/setLevel":                   {},
	"notifications/cancelled":            {},
	"notifications/resources/updated":    {},
	"notifications/tools/list_changed":   {},
	"notifications/prompts/list_changed": {},
	"ping":                               {},
}

// ambiguousMethods lists JSON-RPC method names shared with other protocols
// (e.g. LSP). Each entry maps to a disambiguator function that returns true
// when the request carries an MCP-specific signal beyond the method name.
// The Mcp-Session-Id header is checked before consulting this map; entries
// here only need to handle the no-session-header case.
var ambiguousMethods = map[string]func(json.RawMessage) bool{
	"initialize": hasMCPProtocolVersion,
}

// mcpSessionHeader is the HTTP header that carries the MCP session identifier.
const mcpSessionHeader = "Mcp-Session-Id"

// Param structures for extracting method-specific fields.

type mcpToolCallParams struct {
	Name string `json:"name"`
}

type mcpResourceParams struct {
	URI string `json:"uri"`
}

type mcpPromptParams struct {
	Name string `json:"name"`
}

type mcpInitializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

type mcpInitializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
}

// MCPSpanFromParsed detects MCP signals in a pre-parsed JSON-RPC request and
// enriches the span with MCP-specific attributes. It requires the JSON-RPC
// request to have been parsed by TryParseJSONRPC first. Returns the original
// span and false when the request does not carry MCP signals.
func MCPSpanFromParsed(baseSpan *request.Span, req *http.Request, resp *http.Response, parsed *ParsedJSONRPC) (request.Span, bool) {
	rpcReq := parsed.request

	// MCP requires an explicit JSON-RPC 2.0 version in the body,
	// regardless of Content-Type header detection.
	if rpcReq.JSONRPC != jsonRPCVersion {
		return *baseSpan, false
	}

	sessionID := req.Header.Get(mcpSessionHeader)
	if sessionID == "" && resp != nil && resp.Header != nil {
		sessionID = resp.Header.Get(mcpSessionHeader)
	}

	if _, known := mcpMethods[rpcReq.Method]; !known {
		// Not a recognized MCP method. Check whether the session header
		// was present — that still qualifies the request as MCP even if
		// the method is unknown (e.g. a custom extension method).
		if sessionID == "" {
			return *baseSpan, false
		}
	} else if sessionID == "" {
		// Without the MCP session header, require MCP-specific evidence
		// beyond the method name to avoid misclassifying plain JSON-RPC
		// traffic that happens to use the same method names.
		disambiguate, ok := ambiguousMethods[rpcReq.Method]
		if ok && !disambiguate(rpcReq.Params) {
			return *baseSpan, false
		}
		if !ok {
			// Shared JSON-RPC method names should stay JSON-RPC unless
			// we have some MCP-specific signal beyond the method string.
			return *baseSpan, false
		}
	}

	slog.Debug("MCP", "method", rpcReq.Method, "session", sessionID)

	result := &request.MCPCall{
		Method:    rpcReq.Method,
		SessionID: sessionID,
	}

	if len(rpcReq.ID) > 0 && string(rpcReq.ID) != "null" {
		result.RequestID = rawIDString(rpcReq.ID)
	}

	parseMCPParams(rpcReq, result)

	// Parse response for error and protocol version.
	if resp != nil && resp.Body != nil {
		respB, err := getResponseBody(resp)
		if err == nil && len(respB) > 0 {
			parseMCPResponse(respB, result)
		}
	}

	baseSpan.SubType = request.HTTPSubtypeMCP
	baseSpan.GenAI = &request.GenAI{
		MCP: result,
	}

	return *baseSpan, true
}

// MCPSpan detects and parses an MCP JSON-RPC request/response pair.
// It returns the enriched span and true when the request is a valid MCP call,
// or the original span and false otherwise.
func MCPSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	parsed := TryParseJSONRPC(req)
	if parsed == nil {
		return *baseSpan, false
	}
	return MCPSpanFromParsed(baseSpan, req, resp, parsed)
}

// hasMCPProtocolVersion checks whether the params contain a protocolVersion
// field, which is specific to MCP's initialize method.
func hasMCPProtocolVersion(params json.RawMessage) bool {
	if len(params) == 0 {
		return false
	}
	var p mcpInitializeParams
	return json.Unmarshal(params, &p) == nil && p.ProtocolVersion != ""
}

// parseMCPParams extracts method-specific fields from the request params.
func parseMCPParams(rpcReq jsonRPCRequest, result *request.MCPCall) {
	if len(rpcReq.Params) == 0 {
		return
	}

	switch rpcReq.Method {
	case "tools/call":
		var p mcpToolCallParams
		if json.Unmarshal(rpcReq.Params, &p) == nil {
			result.ToolName = p.Name
		}
	case "resources/read", "resources/subscribe", "resources/unsubscribe":
		var p mcpResourceParams
		if json.Unmarshal(rpcReq.Params, &p) == nil {
			result.ResourceURI = p.URI
		}
	case "prompts/get":
		var p mcpPromptParams
		if json.Unmarshal(rpcReq.Params, &p) == nil {
			result.PromptName = p.Name
		}
	case "initialize":
		var p mcpInitializeParams
		if json.Unmarshal(rpcReq.Params, &p) == nil {
			result.ProtocolVer = p.ProtocolVersion
		}
	}
}

// parseMCPResponse extracts error information and protocol version from the response.
// It handles both single object and batch JSON-RPC responses, reusing
// matchResponse for batch ID matching.
func parseMCPResponse(data []byte, result *request.MCPCall) {
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
		applyMCPResponse(resp, result)
	case '[':
		var batch []jsonRPCResponse
		if err := json.Unmarshal(data, &batch); err != nil {
			return
		}
		if resp, ok := matchResponse(batch, result.RequestID); ok {
			applyMCPResponse(resp, result)
		}
	}
}

// applyMCPResponse extracts MCP-specific fields from a single JSON-RPC response.
func applyMCPResponse(resp jsonRPCResponse, result *request.MCPCall) {
	if resp.Error != nil {
		result.ErrorCode = resp.Error.Code
		result.ErrorMessage = resp.Error.Message
	}

	// For initialize responses, extract the negotiated protocol version.
	if result.Method == "initialize" && len(resp.Result) > 0 {
		var initResult mcpInitializeResult
		if json.Unmarshal(resp.Result, &initResult) == nil && initResult.ProtocolVersion != "" {
			result.ProtocolVer = initResult.ProtocolVersion
		}
	}
}
