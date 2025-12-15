// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type (
	graphQLRequest struct {
		Query        string `json:"query"`
		Mutation     string `json:"mutation"`
		Subscription string `json:"subscription"`
	}
	graphQLOperation struct {
		Type     string // query, mutation, subscription
		Name     string // operation name (if provided)
		Document string // full document string
	}
)

func GraphQLSpan(baseSpan *request.Span, req *http.Request, _ *http.Response) (request.Span, bool) {
	if req.Method != http.MethodPost {
		slog.Debug("parse GraphQL request: unsupported method")
		return *baseSpan, false
	}

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		slog.Debug("read GraphQL request body", "error", err)
		return *baseSpan, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	op, err := parseGraphQLRequest(reqB)
	if err != nil {
		slog.Debug("parse GraphQL request", "error", err)
		return *baseSpan, false
	}

	// https://opentelemetry.io/docs/specs/semconv/graphql/graphql-spans/
	baseSpan.SubType = request.HTTPSubtypeGraphQL
	baseSpan.GraphQL = &request.GraphQL{
		Document:      op.Document,
		OperationName: op.Name,
		OperationType: op.Type,
	}

	return *baseSpan, true
}

func parseGraphQLRequest(data []byte) (graphQLOperation, error) {
	var (
		input string
		req   graphQLRequest
		op    graphQLOperation
	)

	if err := json.Unmarshal(data, &req); err != nil {
		return op, fmt.Errorf("invalid GraphQL JSON body: %w", err)
	}
	if req.Query == "" && req.Mutation == "" && req.Subscription == "" {
		return op, errors.New("no GraphQL operation found")
	}
	if req.Query != "" {
		input = req.Query
	}
	if req.Mutation != "" {
		input = req.Mutation
	}
	if req.Subscription != "" {
		input = req.Subscription
	}

	doc, err := parser.ParseQuery(&ast.Source{Input: input})
	if err != nil {
		return op, fmt.Errorf("failed to parse GraphQL document: %w", err)
	}
	if len(doc.Operations) < 1 {
		return op, errors.New("no GraphQL operations found")
	}

	operation := doc.Operations[0]
	op.Document = input
	op.Name = operation.Name
	op.Type = string(operation.Operation)

	return op, nil
}
