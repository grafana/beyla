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
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// elasticsearchOperation contains only fields related to elasticsearch
type elasticsearchOperation struct {
	NodeName         string
	DBQueryText      string
	DBOperationName  string
	DBCollectionName string
}

const (
	pathSearch string = "_search"
)

func ElasticsearchSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isElasticsearchResponse(resp) {
		return *baseSpan, false
	}
	if err := isSearchRequest(req); err != nil {
		slog.Debug(err.Error())
		return *baseSpan, false
	}

	op, err := parseElasticsearchRequest(req)
	if err != nil {
		slog.Debug("parse Elasticsearch request", "error", err)
		return *baseSpan, false
	}

	if resp != nil {
		if v := resp.Header.Get("X-Found-Handling-Instance"); v != "" {
			op.NodeName = v
		}
	} else {
		op.NodeName = req.URL.Host
	}

	baseSpan.SubType = request.HTTPSubtypeElasticsearch
	baseSpan.Elasticsearch = &request.Elasticsearch{
		NodeName:         op.NodeName,
		DBOperationName:  op.DBOperationName,
		DBCollectionName: op.DBCollectionName,
		DBQueryText:      op.DBQueryText,
	}
	return *baseSpan, true
}

func parseElasticsearchRequest(req *http.Request) (elasticsearchOperation, error) {
	var op elasticsearchOperation
	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return op, fmt.Errorf("failed to read Elasticsearch request body %w", err)
	}

	req.Body = io.NopCloser(bytes.NewBuffer(reqB))
	if len(reqB) == 0 {
		op.DBQueryText = ""
	} else {
		dbQueryText, err := extractDBQueryText(reqB)
		if err != nil {
			return op, err
		}
		op.DBQueryText = dbQueryText
	}
	op.DBOperationName = extractOperationName(req)
	op.DBCollectionName = extractDBCollectionName(req)
	return op, nil
}

func extractDBQueryText(body []byte) (string, error) {
	var buf bytes.Buffer

	if err := json.Compact(&buf, body); err != nil {
		return "", fmt.Errorf("invalid Elasticsearch JSON body: %w", err)
	}

	return buf.String(), nil
}

func isSearchRequest(req *http.Request) error {
	// let's focus only on _search operation that has only GET and POST http methods
	if !strings.Contains(req.URL.Path, pathSearch) {
		return errors.New("parse Elasticsearch search request: unsupported endpoint")
	}

	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		return errors.New("parse Elasticsearch search request: unsupported method")
	}
	return nil
}

// isElasticsearchResponse checks if X-Elastic-Product HTTP header is present.
// Note: this header was introduced in Elasticsearch version 7.14
// For older versions, we just classify it as HTTP
func isElasticsearchResponse(resp *http.Response) bool {
	headerValue := resp.Header.Get("X-Elastic-Product")
	expectedValue := "Elasticsearch"
	return headerValue == expectedValue
}

// extractOperationName is a generic function used to extract the operation name
// that is the endpoint identifier provided in the request
func extractOperationName(req *http.Request) string {
	path := strings.Trim(req.URL.Path, "/")
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return ""
	}
	name := parts[len(parts)-1]
	return strings.TrimPrefix(name, "_")
}

// extractDBCollectionName takes into account this rule from semconv
// The query may target multiple indices or data streams,
// in which case it SHOULD be a comma separated list of those.
// If the query doesn’t target a specific index, this field MUST NOT be set.
func extractDBCollectionName(req *http.Request) string {
	path := strings.Trim(req.URL.Path, "/")
	if path == "" {
		return ""
	}

	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return ""
	}
	first := parts[0]
	if strings.HasPrefix(first, "_") {
		return ""
	}
	return first
}
