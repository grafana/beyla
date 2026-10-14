// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"path/filepath"
	"strings"
)

// This file finds Laravel route definitions, e.g.:
//
//	Route::get('/users', [UserController::class, 'index']);
//	Route::prefix('admin')->group(function () {
//	    Route::get('/dashboard', fn () => ...);
//	});
//
// Call flow:
//
//	extractLaravelRoutes
//	  -> laravelRouteReceivers   finds aliases the "Route" facade was imported as
//	  -> laravelExtractor.extract
//	    -> laravelRouteCall      matches a "<receiver>::<method>(" at one position
//	    -> routeChain            follows ->chained(...) calls after that first one
//	    -> laravelGroup          checks whether the chain is a prefix()/group() pair
//	      -> callbackBody        finds the group's closure body
//	      -> extract             recurses into it with the accumulated prefix
//	    -> extractCall           otherwise dispatches by method name:
//	      -> extractLaravelResource / extractLaravelResourceBatch   (laravel_resource.go)
var laravelPathMethods = map[string]int{
	"any": 0, "delete": 0, "get": 0, "head": 0, "options": 0,
	"patch": 0, "post": 0, "put": 0, "redirect": 0,
	"permanentredirect": 0, "view": 0, "match": 1,
}

type laravelCall struct {
	name      string
	arguments [][]token
	open      int
	close     int
}

type laravelExtractor struct {
	tokens    []token
	receivers map[string]struct{}
	routes    routeSet
}

func extractLaravelRoutes(file phpFile, root string, apiPrefix laravelAPIPrefix, routes routeSet) {
	prefix, resolved := laravelFilePrefix(file.path, root, apiPrefix)
	if !resolved {
		return
	}

	extractor := laravelExtractor{
		tokens:    file.tokens,
		receivers: laravelRouteReceivers(file.tokens),
		routes:    routes,
	}

	extractor.extract(0, len(file.tokens), prefix)
}

func laravelRouteReceivers(tokens []token) map[string]struct{} {
	receivers := map[string]struct{}{
		"\\Illuminate\\Support\\Facades\\Route": {},
		"Illuminate\\Support\\Facades\\Route":   {},
	}

	for pos := 0; pos+1 < len(tokens); pos++ {
		if !equalName(tokens[pos], "use") || !isLaravelRouteFacade(tokens[pos+1].value) {
			continue
		}

		alias := "Route"
		if pos+3 < len(tokens) && equalName(tokens[pos+2], "as") && tokens[pos+3].kind == tokenName {
			alias = tokens[pos+3].value
		}

		receivers[alias] = struct{}{}
	}
	return receivers
}

func (e laravelExtractor) extract(start, end int, prefix string) {
	for pos := start; pos+3 < end; pos++ {
		name, open, ok := laravelRouteCall(e.tokens, pos, e.receivers)
		if !ok {
			continue
		}

		calls := e.routeChain(name, open, end)
		if len(calls) == 0 {
			continue
		}

		if group, groupPrefix, ok := laravelGroup(calls); ok {
			bodyStart, bodyEnd := callbackBody(e.tokens, group)
			if bodyStart >= 0 {
				e.extract(bodyStart+1, bodyEnd, joinRoutes(prefix, groupPrefix))
				pos = bodyEnd
			}
			continue
		}

		e.extractCall(prefix, calls)
		pos = calls[len(calls)-1].close
	}
}

func (e laravelExtractor) extractCall(prefix string, calls []laravelCall) {
	method := strings.ToLower(calls[0].name)
	if argumentIndex, ok := laravelPathMethods[method]; ok {
		path, found := staticStringArgument(calls[0].arguments, argumentIndex)
		if !found {
			path, found = namedLiteralArgument(calls[0].arguments, "uri")
		}

		if found {
			e.routes.add(joinRoutes(prefix, path))
		}

		return
	}

	if isLaravelResourceMethod(method) {
		extractLaravelResource(prefix, method, calls, e.routes)
		return
	}

	if isLaravelResourceBatchMethod(method) {
		extractLaravelResourceBatch(prefix, method, calls, e.routes)
	}
}

func (e laravelExtractor) routeChain(name string, open, end int) []laravelCall {
	endPos := matchingClosingToken(e.tokens, open, "(", ")")
	if endPos < 0 || endPos >= end {
		return nil
	}

	calls := []laravelCall{{name: name, arguments: callArguments(e.tokens, open), open: open, close: endPos}}
	for {
		arrow := skipDocComments(e.tokens, endPos+1, end)
		if arrow+2 >= end ||
			e.tokens[arrow].value != "->" ||
			e.tokens[arrow+1].kind != tokenName ||
			e.tokens[arrow+2].value != "(" {
			break
		}

		open = arrow + 2
		endPos = matchingClosingToken(e.tokens, open, "(", ")")
		if endPos < 0 || endPos >= end {
			break
		}

		calls = append(calls, laravelCall{
			name:      e.tokens[open-1].value,
			arguments: callArguments(e.tokens, open),
			open:      open,
			close:     endPos,
		})
	}
	return calls
}

// skipDocComments advances past any doc comments (e.g. between chained
// method calls) so token-adjacency checks aren't broken by them.
func skipDocComments(tokens []token, pos, end int) int {
	for pos < end && tokens[pos].kind == tokenDocComment {
		pos++
	}

	return pos
}

func laravelGroup(calls []laravelCall) (laravelCall, string, bool) {
	var prefix string
	for _, call := range calls {
		switch strings.ToLower(call.name) {
		case "prefix":
			value, ok := staticStringArgument(call.arguments, 0)
			if !ok {
				value, ok = namedLiteralArgument(call.arguments, "prefix")
			}

			if !ok {
				// The prefix appears to be dynamic and can't be resolved.
				// if we extract the group's routes without it, it would record them under the
				// wrong (unprefixed) path, so we give up on this group entirely.
				return laravelCall{}, "", false
			}

			prefix = joinRoutes(prefix, value)
		case "group":
			value, resolved, present := laravelGroupArrayPrefix(call.arguments)
			if present && !resolved {
				return laravelCall{}, "", false
			}

			if resolved {
				prefix = joinRoutes(prefix, value)
			}

			return call, prefix, true
		}
	}
	return laravelCall{}, "", false
}

// laravelGroupArrayPrefix reads the static "prefix" entry from a group's
// attributes array. the present return value reports whether a "prefix" key exists.
// when present is true, but resolved is false, a prefix is defined but not as
// a plain string literal, and the caller should not treat it as absent.
func laravelGroupArrayPrefix(arguments [][]token) (value string, resolved, present bool) {
	if len(arguments) == 0 {
		return "", false, false
	}

	attributes := arguments[0]
	if namedAttributes, ok := namedArgument(arguments, "attributes"); ok {
		attributes = namedAttributes
	}

	if len(attributes) < 5 || attributes[0].value != "[" || attributes[len(attributes)-1].value != "]" {
		return "", false, false
	}

	for _, item := range splitOnTopLevelCommas(attributes[1 : len(attributes)-1]) {
		if len(item) < 3 || item[0].kind != tokenString || item[0].value != "prefix" || item[1].value != "=>" {
			continue
		}

		if len(item) == 3 && item[2].kind == tokenString {
			return item[2].value, true, true
		}

		return "", false, true
	}
	return "", false, false
}

func callbackBody(tokens []token, call laravelCall) (int, int) {
	// Route::group's callback is always its last argument. we scan only from
	// there to avoid matching a brace that belongs to an earlier argument, such
	// as a closure passed as a middleware value inside the attributes array.
	for pos := lastTopLevelArgumentStart(tokens, call.open, call.close); pos < call.close; pos++ {
		if tokens[pos].kind != tokenSymbol || tokens[pos].value != "{" {
			continue
		}

		end := matchingClosingToken(tokens, pos, "{", "}")
		if end >= 0 && end < call.close {
			return pos, end
		}
	}

	return -1, -1
}

// lastTopLevelArgumentStart returns the position right after the last
// top-level comma inside a call's (open, end) argument list, or open+1
// when the call has only one argument.
func lastTopLevelArgumentStart(tokens []token, open, end int) int {
	start := open + 1
	parenDepth, bracketDepth, braceDepth := 0, 0, 0

	for pos := open + 1; pos < end; pos++ {
		if tokens[pos].kind != tokenSymbol {
			continue
		}

		switch tokens[pos].value {
		case "(":
			parenDepth++
		case ")":
			parenDepth--
		case "[", "#[":
			bracketDepth++
		case "]":
			bracketDepth--
		case "{":
			braceDepth++
		case "}":
			braceDepth--
		case ",":
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				start = pos + 1
			}
		}
	}

	return start
}

func laravelFilePrefix(path, root string, apiPrefix laravelAPIPrefix) (string, bool) {
	relative, err := filepath.Rel(root, path)
	if err != nil || filepath.ToSlash(relative) != "routes/api.php" {
		return "", true
	}

	if apiPrefix.unresolved {
		return "", false
	}

	return apiPrefix.value, true
}

func laravelRouteCall(tokens []token, pos int, receivers map[string]struct{}) (string, int, bool) {
	if pos < 0 || pos+3 >= len(tokens) {
		return "", 0, false
	}

	if tokens[pos].kind != tokenName {
		return "", 0, false
	}

	isReceiver := false
	for receiver := range receivers {
		if strings.EqualFold(receiver, tokens[pos].value) {
			isReceiver = true
			break
		}
	}

	if !isReceiver {
		return "", 0, false
	}

	if tokens[pos+1].value != "::" || tokens[pos+2].kind != tokenName || tokens[pos+3].value != "(" {
		return "", 0, false
	}

	return tokens[pos+2].value, pos + 3, true
}

func isLaravelRouteFacade(name string) bool {
	return strings.EqualFold(strings.TrimPrefix(name, "\\"), "Illuminate\\Support\\Facades\\Route")
}

func equalName(tok token, value string) bool {
	return tok.kind == tokenName && strings.EqualFold(tok.value, value)
}
