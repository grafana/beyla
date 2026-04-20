// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/ohler55/ojg/oj"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
)

// HTTPEnricher applies HTTP enrichment rules to extract headers and body
// content into spans. Rules are split by type at construction time so that
// per-request processing only iterates the relevant subset.
type HTTPEnricher struct {
	headerRules       []config.HTTPParsingRule
	bodyRules         []config.HTTPParsingRule
	policy            config.HTTPParsingPolicy
	obfuscationString string
}

// NewHTTPEnricher creates an enricher from the given config, splitting
// rules by type once so callers don't pay the filtering cost per request.
func NewHTTPEnricher(cfg config.EnrichmentConfig) *HTTPEnricher {
	e := &HTTPEnricher{
		policy:            cfg.Policy,
		obfuscationString: cfg.Policy.ObfuscationString,
	}
	for _, rule := range cfg.Rules {
		switch rule.Type {
		case config.HTTPParsingRuleTypeHeaders:
			e.headerRules = append(e.headerRules, rule)
		case config.HTTPParsingRuleTypeBody:
			e.bodyRules = append(e.bodyRules, rule)
		}
	}
	return e
}

// Enrich applies header and body extraction rules to the span.
// Returns true if any content was extracted.
func (e *HTTPEnricher) Enrich(
	baseSpan *request.Span,
	req *http.Request,
	resp *http.Response,
) bool {
	reqHeaders := e.processHeaders(req.Header, config.HTTPParsingScopeRequest, baseSpan)
	respHeaders := e.processHeaders(resp.Header, config.HTTPParsingScopeResponse, baseSpan)

	reqBody := e.processBody(req.Header, readRequestBody(req), config.HTTPParsingScopeRequest, baseSpan)
	respBody := e.processBody(resp.Header, readResponseBody(resp), config.HTTPParsingScopeResponse, baseSpan)

	hasContent := len(reqHeaders) > 0 || len(respHeaders) > 0 || reqBody != "" || respBody != ""
	if !hasContent {
		return false
	}

	if len(reqHeaders) > 0 {
		baseSpan.RequestHeaders = reqHeaders
	}
	if len(respHeaders) > 0 {
		baseSpan.ResponseHeaders = respHeaders
	}
	if reqBody != "" {
		baseSpan.RequestBodyContent = reqBody
	}
	if respBody != "" {
		baseSpan.ResponseBodyContent = respBody
	}
	return true
}

// processHeaders evaluates header rules and returns a map of headers to
// include or obfuscate. The map is allocated lazily.
func (e *HTTPEnricher) processHeaders(
	headers http.Header,
	scope config.HTTPParsingScope,
	span *request.Span,
) map[string][]string {
	var result map[string][]string
	for name, values := range headers {
		action := e.resolveHeaderAction(name, scope, span)
		if action == config.HTTPParsingActionExclude {
			continue
		}
		if result == nil {
			result = make(map[string][]string)
		}
		applyHeaderAction(action, name, values, result, e.obfuscationString)
	}
	return result
}

// resolveHeaderAction determines what action to take for a given header name
// by evaluating header rules in order (first match wins).
func (e *HTTPEnricher) resolveHeaderAction(
	headerName string,
	scope config.HTTPParsingScope,
	span *request.Span,
) config.HTTPParsingAction {
	var lowerName string

	for _, rule := range e.headerRules {
		if !ruleApplies(rule, scope, span) {
			continue
		}
		matchName := headerName
		if !rule.Match.CaseSensitive {
			if lowerName == "" {
				lowerName = strings.ToLower(headerName)
			}
			matchName = lowerName
		}
		for i := range rule.Match.Patterns {
			if rule.Match.Patterns[i].MatchString(matchName) {
				return rule.Action
			}
		}
	}
	return e.policy.DefaultAction.Headers
}

// readRequestBody returns a function that reads and resets the request body.
func readRequestBody(req *http.Request) func() ([]byte, error) {
	return func() ([]byte, error) {
		if req.Body == nil {
			return nil, nil
		}
		bodyBytes, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		return bodyBytes, nil
	}
}

// readResponseBody returns a function that reads, decompresses, and resets the response body.
func readResponseBody(resp *http.Response) func() ([]byte, error) {
	return func() ([]byte, error) {
		if resp.Body == nil {
			return nil, nil
		}
		return getResponseBody(resp)
	}
}

// processBody evaluates body rules and returns the body content string (possibly obfuscated).
// All matching body rules are merged (unlike headers which use first-match-wins).
// Rule precedence: exclude > obfuscate > include. If any matching rule excludes, the body is excluded.
func (e *HTTPEnricher) processBody(
	headers http.Header,
	readBody func() ([]byte, error),
	scope config.HTTPParsingScope,
	span *request.Span,
) string {
	if !isJSONContentType(headers.Get("Content-Type")) {
		return ""
	}

	// Collect all matching body rules
	hasInclude := false
	hasExclude := false
	var allJSONPaths []config.JSONPathExpr

	matched := false
	for _, rule := range e.bodyRules {
		if !ruleApplies(rule, scope, span) {
			continue
		}

		matched = true
		switch rule.Action {
		case config.HTTPParsingActionExclude:
			hasExclude = true
		case config.HTTPParsingActionInclude:
			hasInclude = true
		case config.HTTPParsingActionObfuscate:
			allJSONPaths = append(allJSONPaths, rule.Match.ObfuscationJSONPaths...)
		}
	}

	// Determine effective action
	var effectiveAction config.HTTPParsingAction
	switch {
	case !matched:
		effectiveAction = e.policy.DefaultAction.Body
	case hasExclude:
		effectiveAction = config.HTTPParsingActionExclude
	case len(allJSONPaths) > 0:
		effectiveAction = config.HTTPParsingActionObfuscate
	case hasInclude:
		effectiveAction = config.HTTPParsingActionInclude
	default:
		effectiveAction = config.HTTPParsingActionExclude
	}

	if effectiveAction == config.HTTPParsingActionExclude {
		return ""
	}

	// Read body (handles decompression for responses)
	bodyBytes, err := readBody()
	if err != nil || len(bodyBytes) == 0 {
		return ""
	}

	if effectiveAction == config.HTTPParsingActionInclude {
		if !json.Valid(bodyBytes) {
			return ""
		}
		return string(bodyBytes)
	}

	// Obfuscate: parse, apply paths, re-serialize
	parsed, err := oj.Parse(bodyBytes)
	if err != nil {
		return ""
	}

	for i := range allJSONPaths {
		if err := allJSONPaths[i].Expr().Set(parsed, e.obfuscationString); err != nil {
			// Unmatched paths are silently ignored — Set returns error only for structural issues
			continue
		}
	}

	return oj.JSON(parsed)
}

// ruleApplies returns true if the rule matches the given scope, path, and method.
func ruleApplies(rule config.HTTPParsingRule, scope config.HTTPParsingScope, span *request.Span) bool {
	return scopeApplies(rule.Scope, scope) &&
		urlPathMatches(rule.Match.URLPathPatterns, span.Path) &&
		methodMatches(rule.Match.Methods, span.Method)
}

// scopeApplies returns true if the rule scope covers the given header source.
func scopeApplies(ruleScope config.HTTPParsingScope, headerSource config.HTTPParsingScope) bool {
	return ruleScope == config.HTTPParsingScopeAll || ruleScope == headerSource
}

// applyHeaderAction adds the header to the map based on the resolved action.
func applyHeaderAction(
	action config.HTTPParsingAction,
	name string,
	values []string,
	headers map[string][]string,
	obfuscationString string,
) {
	switch action {
	case config.HTTPParsingActionInclude:
		headers[name] = append(headers[name], values...)
	case config.HTTPParsingActionObfuscate:
		headers[name] = []string{obfuscationString}
	case config.HTTPParsingActionExclude:
		// do nothing
	}
}

// isJSONContentType checks if the Content-Type header indicates JSON content.
func isJSONContentType(contentType string) bool {
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// urlPathMatches returns true if the request path matches any of the URL path patterns.
// If no patterns are specified, all paths match.
func urlPathMatches(patterns []services.GlobAttr, path string) bool {
	if len(patterns) == 0 {
		return true
	}
	for i := range patterns {
		if patterns[i].MatchString(path) {
			return true
		}
	}
	return false
}

// methodMatches returns true if the request method matches any of the specified methods.
// If no methods are specified, all methods match.
func methodMatches(methods []config.HTTPMethod, method string) bool {
	if len(methods) == 0 {
		return true
	}
	upper := config.HTTPMethod(strings.ToUpper(method))
	for _, m := range methods {
		if m == upper {
			return true
		}
	}
	return false
}
