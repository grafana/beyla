// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"strings"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

const (
	rpcMethodOther = "_OTHER"

	// unreadGRPCPath is the path the HTTP/2 parser reports when it could not
	// read a usable :path header.
	unreadGRPCPath = "*"
)

var grpcSystemName = semconv.RPCSystemNameGRPC.Value.AsString()

func GRPCMethod(s *Span) (method, original string) {
	if s.Path == "" || s.Path == unreadGRPCPath {
		return rpcMethodOther, ""
	}

	fullMethod, isPath := strings.CutPrefix(s.Path, "/")
	if !isPath || !isGRPCFullMethod(fullMethod) {
		return rpcMethodOther, s.Path
	}

	return fullMethod, ""
}

func isGRPCFullMethod(fullMethod string) bool {
	service, name, ok := strings.Cut(fullMethod, "/")

	return ok && service != "" && name != "" && !strings.Contains(name, "/")
}

func grpcSpanName(s *Span) string {
	method, _ := GRPCMethod(s)
	if method == rpcMethodOther {
		return grpcSystemName
	}

	return method
}
