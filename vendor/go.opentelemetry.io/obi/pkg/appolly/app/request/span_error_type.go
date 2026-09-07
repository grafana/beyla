// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"strconv"

	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
)

const ErrorTypeOther = "_OTHER"

// SpanErrorType returns error.type for a failed span, or "" when the span did
// not fail. It is the single source for the trace and the metric pipeline.
func SpanErrorType(span *Span) string {
	if errType := parsedErrorType(span); errType != "" {
		return errType
	}

	if SpanStatusCode(span) != StatusCodeError {
		return ""
	}

	switch span.Type {
	case EventTypeHTTP, EventTypeHTTPClient:
		if span.Status >= 400 {
			return strconv.Itoa(span.Status)
		}
	case EventTypeGRPC, EventTypeGRPCClient:
		if code := GRPCStatusCodeString(span.Status); code != "" {
			return code
		}
	case EventTypeSunRPCClient, EventTypeSunRPCServer:
		return SunRPCResponseStatusCode(span.Status)
	case EventTypeDNS:
		return dnsparser.RCode(span.Status).String()
	}

	return ErrorTypeOther
}

// parsedErrorType reports the error a protocol parser extracted from the
// payload, which some protocols report inside a 2xx response.
func parsedErrorType(span *Span) string {
	if span.DBError.ErrorCode != "" {
		return span.DBError.ErrorCode
	}
	if span.SQLError != nil {
		// Semconv prefers the vendor code and falls back to SQLSTATE; MySQL
		// reports the code unconditionally but SQLSTATE only under
		// CLIENT_PROTOCOL_41.
		if span.SQLError.SQLState != "" {
			return span.SQLError.SQLState
		}
		if span.SQLError.Code != 0 {
			return strconv.Itoa(int(span.SQLError.Code))
		}
	}
	if errType := span.GenAIErrorType(); errType != "" {
		return errType
	}
	if span.SubType == HTTPSubtypeJSONRPC && span.JSONRPC != nil && span.JSONRPC.ErrorCode != 0 {
		return strconv.Itoa(span.JSONRPC.ErrorCode)
	}
	if span.SubType == HTTPSubtypeMCP && span.GenAI != nil && span.GenAI.MCP != nil &&
		span.GenAI.MCP.ErrorCode != 0 {
		return strconv.Itoa(span.GenAI.MCP.ErrorCode)
	}

	return ""
}
