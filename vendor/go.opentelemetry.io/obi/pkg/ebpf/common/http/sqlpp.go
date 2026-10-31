// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	jsoniter "github.com/json-iterator/go"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/split"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

const (
	sqlppOperationPrepare = "PREPARE"
	sqlppOperationExecute = "EXECUTE"
)

type sqlppRequest struct {
	Statement   string
	QueryCtx    string
	Prepared    string
	AutoExecute bool
}

type sqlppRequestBody struct {
	Statement   string          `json:"statement"`
	QueryCtx    string          `json:"query_context"`
	Prepared    json.RawMessage `json:"prepared"`
	AutoExecute json.RawMessage `json:"auto_execute"`
}

type sqlppDestination struct {
	host string
	port int
}

type sqlppPreparedKey struct {
	pid         app.PID
	destination sqlppDestination
	queryCtx    string
	name        string
}

type SQLPPPreparedStatements struct {
	cache *lru.Cache[sqlppPreparedKey, string]
}

func NewSQLPPPreparedStatements(size int) (*SQLPPPreparedStatements, error) {
	cache, err := lru.New[sqlppPreparedKey, string](size)
	if err != nil {
		return nil, err
	}
	return &SQLPPPreparedStatements{cache: cache}, nil
}

func (p *SQLPPPreparedStatements) store(key sqlppPreparedKey, statement string) {
	if p == nil || key.name == "" || statement == "" {
		return
	}
	p.cache.Add(key, statement)
}

func (p *SQLPPPreparedStatements) lookup(key sqlppPreparedKey) (string, bool) {
	if p == nil || key.name == "" {
		return "", false
	}
	return p.cache.Get(key)
}

// sqlppResponse represents the JSON structure of a SQL++ query response
type sqlppResponse struct {
	Status string       `json:"status"`
	Errors []sqlppError `json:"errors"`
}

// sqlppError represents an error in a SQL++ response
type sqlppError struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

// SQLPPSpan detects and enriches SQL++ spans (Couchbase and other SQL++ databases)
func SQLPPSpan(baseSpan *request.Span, req *http.Request, resp *http.Response, endpointPatterns []string, prepared *SQLPPPreparedStatements) (request.Span, bool) {
	// Must match endpoint pattern first
	if !matchesEndpointPattern(req, endpointPatterns) {
		return *baseSpan, false
	}

	sqlppInfo, err := parseSQLPPRequest(req)
	if err != nil {
		slog.Debug("parse SQL++ request", "error", err)
		return *baseSpan, false
	}

	// Determine db system: N1QL header means Couchbase, otherwise other_sql
	dbSystem := "other_sql"
	if hasN1QLVersion(resp) {
		dbSystem = "couchbase"
	}

	respBody := readSQLPPResponseBody(resp)
	errInfo := parseSQLPPResponse(respBody)
	result := sqlppResult{
		body:      respBody,
		httpOK:    resp != nil && resp.StatusCode == http.StatusOK,
		succeeded: errInfo == nil,
	}
	scope := sqlppPreparedScope{
		statements:  prepared,
		pid:         baseSpan.Pid.HostPID,
		destination: sqlppDestination{host: baseSpan.Host, port: baseSpan.HostPort},
	}
	statement, forcedOperation := resolveSQLPPStatement(sqlppInfo, result, scope)

	// Use the standard SQL parser to extract operation and table
	operation, table := sqlprune.SQLParseOperationAndTable(statement)
	if forcedOperation != "" {
		operation = forcedOperation
	}
	if operation == "" {
		operation = "query" // default operation
	}

	// Parse the table path into bucket and collection
	// Format: bucket.scope.collection or just identifier
	bucket, collection := parseSQLPPTablePath(table, sqlppInfo.QueryCtx != "")

	// If bucket not in table path, try to get from query_context or request fields
	if bucket == "" {
		bucket = extractSQLPPNamespace(sqlppInfo)
	}

	// Use existing span fields for SQL-like attributes
	// Note: Don't overwrite Path - it's needed for url.full (the HTTP route)
	baseSpan.SubType = request.HTTPSubtypeSQLPP
	baseSpan.Route = collection    // db.collection.name (scope.collection)
	baseSpan.Statement = statement // db.query.text
	baseSpan.DBNamespace = bucket  // db.namespace (bucket)
	baseSpan.DBSystem = dbSystem   // db.system.name
	baseSpan.Method = operation    // db.operation.name

	if errInfo != nil {
		baseSpan.DBError = *errInfo
	}

	return *baseSpan, true
}

// matchesEndpointPattern checks if request URL matches any endpoint pattern
func matchesEndpointPattern(req *http.Request, patterns []string) bool {
	if req == nil || len(patterns) == 0 {
		return false
	}
	path := req.URL.Path
	for _, pattern := range patterns {
		if strings.HasSuffix(path, pattern) || path == pattern {
			return true
		}
	}
	return false
}

// hasN1QLVersion checks if the response Content-Type header contains a version parameter
// that ends with "-N1QL" (e.g., "version=2.0.0-N1QL"), indicating Couchbase
func hasN1QLVersion(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	contentType := resp.Header.Get("Content-Type")
	// Split by semicolons to get individual parameters
	iter := split.NewStringIterator(contentType, ";")
	for part, eof := iter.Next(); !eof; part, eof = iter.Next() {
		part = strings.TrimSuffix(part, ";")
		part = strings.TrimSpace(part)
		// Look for version= parameter
		if strings.HasPrefix(strings.ToLower(part), "version=") {
			// Extract the version value
			value := strings.TrimPrefix(part, part[:8]) // Remove "version=" (case-insensitive handled by HasPrefix)
			return strings.HasSuffix(value, "-N1QL")
		}
	}
	return false
}

// parseSQLPPTablePath parses a SQL++ table path into bucket and collection
// Format: `bucket`.`scope`.`collection` -> bucket="bucket", collection="scope.collection"
// Format: `identifier` with hasQueryContext=true -> bucket="", collection="identifier"
// Format: `identifier` with hasQueryContext=false -> bucket="identifier", collection=""
func parseSQLPPTablePath(table string, hasQueryContext bool) (bucket, collection string) {
	if table == "" {
		return "", ""
	}

	// Count parts first
	iter := split.NewStringIterator(table, ".")
	count := 0
	for _, eof := iter.Next(); !eof; _, eof = iter.Next() {
		count++
	}

	switch count {
	case 1:
		// Just a single identifier - interpretation depends on context
		if hasQueryContext {
			// When query_context is set, this is the collection name
			return "", table
		}
		// When no query_context, this is the bucket name (legacy mode)
		return table, ""
	case 3:
		// bucket.scope.collection - extract parts inline
		iter.Reset()
		part0, _ := iter.Next()
		part1, _ := iter.Next()
		part2, _ := iter.Next()
		return strings.TrimSuffix(part0, "."), strings.TrimSuffix(part1, ".") + "." + part2
	default:
		// Unexpected format, return as-is
		return "", table
	}
}

// parseSQLPPRequest parses the SQL++ query request body
func parseSQLPPRequest(req *http.Request) (*sqlppRequest, error) {
	if req == nil || req.Body == nil {
		return nil, errors.New("nil request or body")
	}

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read SQL++ request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	var sqlppReq sqlppRequest

	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		// Handle form-encoded requests
		sqlppReq.Statement = unescapeSQLPPFormValue(extractFormValue(string(reqB), "statement"))
		sqlppReq.QueryCtx = unescapeSQLPPFormValue(extractFormValue(string(reqB), "query_context"))
		sqlppReq.Prepared = unquoteSQLPPIdentifier(unescapeSQLPPFormValue(extractFormValue(string(reqB), "prepared")))
		sqlppReq.AutoExecute = isSQLPPTrue(unescapeSQLPPFormValue(extractFormValue(string(reqB), "auto_execute")))
	} else {
		// Handle JSON requests
		var body sqlppRequestBody
		if err := json.Unmarshal(reqB, &body); err != nil {
			// Try to extract statement from raw body if JSON parsing fails
			sqlppReq.Statement = string(reqB)
		} else {
			sqlppReq.Statement = body.Statement
			sqlppReq.QueryCtx = body.QueryCtx
			sqlppReq.Prepared = sqlppPreparedName(body.Prepared)
			sqlppReq.AutoExecute = isSQLPPTrue(string(body.AutoExecute))
		}
	}

	if sqlppReq.Statement == "" && sqlppReq.Prepared == "" {
		return nil, errors.New("no statement found in SQL++ request")
	}

	return &sqlppReq, nil
}

func sqlppPreparedName(raw json.RawMessage) string {
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return ""
	}
	return name
}

func isSQLPPTrue(value string) bool {
	return strings.EqualFold(strings.Trim(value, `"`), "true")
}

func unescapeSQLPPFormValue(value string) string {
	if unescaped, err := url.QueryUnescape(value); err == nil {
		return unescaped
	}
	return value
}

type sqlppResult struct {
	body      []byte
	httpOK    bool
	succeeded bool
}

type sqlppPreparedScope struct {
	statements  *SQLPPPreparedStatements
	pid         app.PID
	destination sqlppDestination
}

func (p sqlppPreparedScope) key(destination sqlppDestination, queryCtx, name string) sqlppPreparedKey {
	return sqlppPreparedKey{pid: p.pid, destination: destination, queryCtx: queryCtx, name: name}
}

func (p sqlppPreparedScope) storeServerNamed(queryCtx, name, statement string) {
	p.statements.store(p.key(sqlppDestination{}, queryCtx, name), statement)
}

func (p sqlppPreparedScope) storeClientNamed(queryCtx, name, statement string) {
	p.statements.store(p.key(p.destination, queryCtx, name), statement)
}

func (p sqlppPreparedScope) lookup(queryCtx, name string) (string, bool) {
	if text, ok := p.statements.lookup(p.key(p.destination, queryCtx, name)); ok {
		return text, true
	}
	return p.statements.lookup(p.key(sqlppDestination{}, queryCtx, name))
}

func resolveSQLPPStatement(info *sqlppRequest, result sqlppResult, prepared sqlppPreparedScope) (statement, forcedOperation string) {
	if info.Statement == "" {
		if text, ok := prepared.lookup(info.QueryCtx, info.Prepared); ok {
			return text, ""
		}
		return "", sqlppOperationExecute
	}

	if prepareName, inner, ok := parseSQLPPPrepare(info.Statement); ok {
		switch {
		case prepareName == "" && result.httpOK:
			prepared.storeServerNamed(info.QueryCtx, preparedNameFromSQLPPResponse(result.body, info.AutoExecute), inner)
		case prepareName != "" && result.succeeded:
			prepared.storeClientNamed(info.QueryCtx, prepareName, inner)
		}
		if info.AutoExecute {
			return inner, ""
		}
		return inner, sqlppOperationPrepare
	}

	executeName, ok := parseSQLPPExecute(info.Statement)
	if !ok {
		return info.Statement, ""
	}
	if text, found := prepared.lookup(info.QueryCtx, executeName); found {
		return text, ""
	}
	return info.Statement, sqlppOperationExecute
}

var sqlppStatementKeywords = []string{"SELECT", "INSERT", "UPSERT", "UPDATE", "DELETE", "MERGE", "WITH", "INFER"}

func startsSQLPPStatement(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "(") {
		return true
	}
	for _, keyword := range sqlppStatementKeywords {
		if len(s) >= len(keyword) && strings.EqualFold(s[:len(keyword)], keyword) &&
			(len(s) == len(keyword) || isSQLPPSpace(s[len(keyword)]) || s[len(keyword)] == '(') {
			return true
		}
	}
	return false
}

func parseSQLPPPrepare(statement string) (name, inner string, ok bool) {
	rest, ok := cutSQLPPKeyword(statement, sqlppOperationPrepare)
	if !ok {
		return "", "", false
	}
	if afterForce, forced := cutSQLPPKeyword(rest, "FORCE"); forced {
		rest = afterForce
	}
	if token, after, found := nextSQLPPToken(rest); found {
		for _, keyword := range []string{"FROM", "AS"} {
			if body, named := cutSQLPPKeyword(after, keyword); named && startsSQLPPStatement(body) {
				return unquoteSQLPPIdentifier(token), body, true
			}
		}
	}
	return "", rest, true
}

func parseSQLPPExecute(statement string) (string, bool) {
	rest, ok := cutSQLPPKeyword(statement, sqlppOperationExecute)
	if !ok {
		return "", false
	}
	token, _, found := nextSQLPPToken(rest)
	if !found || strings.EqualFold(token, "FUNCTION") {
		return "", false
	}
	return unquoteSQLPPIdentifier(token), true
}

func cutSQLPPKeyword(s, keyword string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) <= len(keyword) || !strings.EqualFold(s[:len(keyword)], keyword) || !isSQLPPSpace(s[len(keyword)]) {
		return "", false
	}
	rest := strings.TrimSpace(s[len(keyword):])
	return rest, rest != ""
}

func nextSQLPPToken(s string) (token, rest string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	if quote := s[0]; quote == '`' || quote == '"' || quote == '\'' {
		end := strings.IndexByte(s[1:], quote)
		if end < 0 {
			return "", "", false
		}
		return s[:end+2], s[end+2:], true
	}
	end := strings.IndexAny(s, " \t\n\r")
	if end < 0 {
		return s, "", true
	}
	return s[:end], s[end:], true
}

func isSQLPPSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func unquoteSQLPPIdentifier(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if first, last := s[0], s[len(s)-1]; first == last && (first == '`' || first == '"' || first == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func readSQLPPResponseBody(resp *http.Response) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	body, err := getResponseBody(resp)
	if err != nil {
		slog.Debug("partial SQL++ response body", "error", err, "bytes", len(body))
	}
	return body
}

func preparedNameFromSQLPPResponse(body []byte, autoExecute bool) string {
	if len(body) == 0 {
		return ""
	}
	if name := extractJSONStringField(body, "prepared", 0); name != "" {
		return name
	}
	if autoExecute {
		return ""
	}
	if name := jsonBestEffort.Get(body, "results", 0, "name"); name.ValueType() == jsoniter.StringValue {
		return name.ToString()
	}
	return ""
}

// extractFormValue extracts a value from form-encoded data
func extractFormValue(data, key string) string {
	iter := split.NewStringIterator(data, "&")
	for pair, eof := iter.Next(); !eof; pair, eof = iter.Next() {
		pair = strings.TrimSuffix(pair, "&")
		// Split by first "=" only (equivalent to SplitN with 2)
		idx := strings.Index(pair, "=")
		if idx > 0 && pair[:idx] == key {
			// URL decode the value
			return strings.ReplaceAll(pair[idx+1:], "+", " ")
		}
	}
	return ""
}

// extractSQLPPNamespace extracts namespace (bucket) from SQL++ request
func extractSQLPPNamespace(sqlppReq *sqlppRequest) string {
	if sqlppReq.QueryCtx == "" {
		return ""
	}

	ctx := sqlppReq.QueryCtx

	// Strip "default:" prefix if present
	ctx = strings.TrimPrefix(ctx, "default:")

	// Extract the first identifier (bucket name)
	// Handle backtick-quoted: `bucket`.`scope` or `bucket`
	if strings.HasPrefix(ctx, "`") {
		end := strings.Index(ctx[1:], "`")
		if end > 0 {
			return ctx[1 : end+1]
		}
	}

	// Handle unquoted: bucket.scope or bucket
	if idx := strings.Index(ctx, "."); idx > 0 {
		return ctx[:idx]
	}

	return ctx
}

// parseSQLPPResponse parses the SQL++ response body for errors
func parseSQLPPResponse(respB []byte) *request.DBError {
	if len(respB) == 0 {
		return nil
	}

	var sqlppResp sqlppResponse
	if err := json.Unmarshal(respB, &sqlppResp); err != nil {
		slog.Debug("failed to parse SQL++ response", "error", err)
		return nil
	}

	// Only check for errors if status is not success
	if sqlppResp.Status == "success" {
		return nil
	}

	// Check for errors in the response
	if len(sqlppResp.Errors) > 0 {
		firstErr := sqlppResp.Errors[0]
		return &request.DBError{
			ErrorCode:   strconv.Itoa(firstErr.Code),
			Description: firstErr.Msg,
		}
	}

	return nil
}
