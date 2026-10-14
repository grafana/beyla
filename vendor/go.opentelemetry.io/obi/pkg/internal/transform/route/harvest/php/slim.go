// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"maps"
	"strings"
)

// Slim routes are registered through an App or RouteCollectorProxy:
//
//	$app->get('/users/{id}', UserHandler::class);
//	$app->map(['GET', 'POST'], '/users', UserHandler::class);
//	$app->redirect('/old-users', '/users');
//	$app->group('/api', function (RouteCollectorProxy $group) {
//	    $group->post('/users', UserHandler::class);
//	});
//
// Processing:
//
//	extractSlimRoutes
//	 -> slimClassAliases
//	 -> slimVariables
//	 -> slimBasePath
//	 -> slimExtractor.extract
//	    -> slimRouteCall
//	    -> slimRoutePath -> slimRouteVariants
//	    -> slimExtractor.extractGroup
//	       -> slimCallbackBody / slimCallbackVariable
//	       -> slimRouteVariants (the group's own pattern)
//	       -> slimExtractor.extract for nested routes, once per resolved prefix
var slimRoutePathArgs = map[string]int{
	"any": 0, "delete": 0, "get": 0, "options": 0,
	"patch": 0, "post": 0, "put": 0, "redirect": 0, "map": 1,
}

type slimCall struct {
	name      string
	arguments [][]token
	open      int
	close     int
}

type slimExtractor struct {
	tokens []token
	routes routeSet
}

func extractSlimRoutes(tokens []token, routes routeSet) {
	aliases := slimClassAliases(tokens)
	variables := slimVariables(tokens, aliases)
	prefix := slimBasePath(tokens, variables)
	extractor := slimExtractor{tokens: tokens, routes: routes}
	extractor.extract(0, len(tokens), variables, prefix, false)
}

func (e slimExtractor) extract(start, end int, variables map[string]struct{}, prefix string, allowThis bool) {
	for pos := start; pos+3 < end; pos++ {
		call, ok := slimRouteCall(e.tokens, pos, end, variables, allowThis)
		if !ok {
			continue
		}

		if strings.EqualFold(call.name, "group") {
			e.extractGroup(call, variables, prefix)
			_, bodyEnd := slimCallbackBody(e.tokens, call)
			if bodyEnd >= 0 {
				pos = bodyEnd
			}
			continue
		}

		if path, ok := slimRoutePath(call); ok {
			for _, route := range slimRouteVariants(joinRoutes(prefix, path)) {
				e.routes.add(route)
			}
		}

		pos = call.close
	}
}

func slimRoutePath(call slimCall) (string, bool) {
	method := strings.ToLower(call.name)
	argPos, ok := slimRoutePathArgs[method]
	if !ok {
		return "", false
	}

	if path, ok := staticStringArgument(call.arguments, argPos); ok {
		return path, true
	}

	argName := "pattern"
	if method == "redirect" {
		argName = "from"
	}

	return namedLiteralArgument(call.arguments, argName)
}

func (e slimExtractor) extractGroup(call slimCall, variables map[string]struct{}, prefix string) {
	groupPrefix, ok := staticStringArgument(call.arguments, 0)
	if !ok {
		groupPrefix, ok = namedLiteralArgument(call.arguments, "pattern")
	}

	if !ok {
		return
	}

	bodyStart, bodyEnd := slimCallbackBody(e.tokens, call)
	if bodyStart < 0 {
		return
	}

	callbackVars := maps.Clone(variables)
	variable, hasVariable := slimCallbackVariable(e.tokens, call.open, bodyStart)
	if hasVariable {
		callbackVars[variable] = struct{}{}
	}

	// A group's own pattern can carry optional segments too (e.g. "/api[/v2]"),
	// so every route nested inside it must be extracted once per resolved prefix.
	for _, resolvedPrefix := range slimRouteVariants(groupPrefix) {
		e.extract(bodyStart+1, bodyEnd, callbackVars, joinRoutes(prefix, resolvedPrefix), !hasVariable)
	}
}

func slimRouteCall(tokens []token, pos, end int, variables map[string]struct{}, allowThis bool) (slimCall, bool) {
	if pos < 0 || pos >= end || pos >= len(tokens) {
		return slimCall{}, false
	}

	if tokens[pos].kind != tokenVariable {
		return slimCall{}, false
	}

	_, knownVariable := variables[tokens[pos].value]
	isThis := allowThis && tokens[pos].value == "$this"
	if !knownVariable && !isThis {
		return slimCall{}, false
	}

	// A doc comment (e.g. documenting one call in a chain) may sit between
	// the receiver and "->". we skip past it before checking adjacency.
	arrow := skipDocComments(tokens, pos+1, end)
	if arrow+2 >= end || tokens[arrow].value != "->" || tokens[arrow+1].kind != tokenName || tokens[arrow+2].value != "(" {
		return slimCall{}, false
	}

	open := arrow + 2
	endPos := matchingClosingToken(tokens, open, "(", ")")
	if endPos < 0 || endPos >= end {
		return slimCall{}, false
	}

	return slimCall{
		name:      tokens[arrow+1].value,
		arguments: callArguments(tokens, open),
		open:      open,
		close:     endPos,
	}, true
}

func slimCallbackBody(tokens []token, call slimCall) (int, int) {
	decl := slimCallbackDeclaration(tokens, call.open+1, call.close)
	if decl < 0 || decl+1 >= call.close || tokens[decl+1].value != "(" {
		return -1, -1
	}

	paramsEnd := matchingClosingToken(tokens, decl+1, "(", ")")
	if paramsEnd < 0 || paramsEnd >= call.close {
		return -1, -1
	}

	if equalName(tokens[decl], "fn") {
		// Arrow callbacks have no braces, so the group call closes their body.
		for pos := paramsEnd + 1; pos < call.close; pos++ {
			if tokens[pos].value == "=>" {
				return pos, call.close
			}
		}

		return -1, -1
	}

	for pos := paramsEnd + 1; pos < call.close; pos++ {
		if tokens[pos].value != "{" {
			continue
		}

		end := matchingClosingToken(tokens, pos, "{", "}")
		if end >= 0 && end < call.close {
			return pos, end
		}
	}

	return -1, -1
}

func slimCallbackVariable(tokens []token, start, end int) (string, bool) {
	decl := slimCallbackDeclaration(tokens, start, end)
	if decl < 0 || decl+1 >= end || tokens[decl+1].value != "(" {
		return "", false
	}

	paramsEnd := matchingClosingToken(tokens, decl+1, "(", ")")
	if paramsEnd < 0 || paramsEnd > end {
		return "", false
	}

	// Slim passes only the first group callback argument as the route proxy.
	for pos := decl + 2; pos < paramsEnd; pos++ {
		if tokens[pos].kind == tokenVariable {
			return tokens[pos].value, true
		}
	}

	return "", false
}

func slimCallbackDeclaration(tokens []token, start, end int) int {
	closure := nextNamedToken(tokens, start, end, "function")
	arrow := nextNamedToken(tokens, start, end, "fn")
	if arrow >= 0 && (closure < 0 || arrow < closure) {
		return arrow
	}

	return closure
}

func slimBasePath(tokens []token, variables map[string]struct{}) string {
	var prefix string
	for pos := 0; pos+3 < len(tokens); pos++ {
		if tokens[pos].kind != tokenVariable {
			continue
		}

		if _, ok := variables[tokens[pos].value]; !ok {
			continue
		}

		if tokens[pos+1].value != "->" || !equalName(tokens[pos+2], "setBasePath") || tokens[pos+3].value != "(" {
			continue
		}

		arguments := callArguments(tokens, pos+3)
		// A later dynamic value makes an earlier static base path stale.
		prefix = ""
		value, ok := staticStringArgument(arguments, 0)
		if !ok {
			value, ok = namedLiteralArgument(arguments, "basePath")
		}

		if ok {
			prefix = value
		}
	}
	return prefix
}

func slimVariables(tokens []token, aliases map[string]string) map[string]struct{} {
	variables := map[string]struct{}{}
	for pos := range len(tokens) {
		isTypedRouter := pos+1 < len(tokens) &&
			tokens[pos].kind == tokenName &&
			tokens[pos+1].kind == tokenVariable &&
			isSlimRouterType(tokens[pos].value, aliases)
		if isTypedRouter {
			variables[tokens[pos+1].value] = struct{}{}
		}

		if tokens[pos].kind != tokenVariable || pos+3 >= len(tokens) || tokens[pos+1].value != "=" {
			continue
		}

		if equalName(tokens[pos+2], "new") && isSlimApp(tokens[pos+3].value, aliases) {
			variables[tokens[pos].value] = struct{}{}
			continue
		}

		isFactory := isSlimAppFactory(tokens[pos+2].value, aliases) && tokens[pos+3].value == "::"
		callsCreate := pos+5 < len(tokens) && equalName(tokens[pos+4], "create") && tokens[pos+5].value == "("
		if isFactory && callsCreate {
			variables[tokens[pos].value] = struct{}{}
		}
	}
	return variables
}

func slimClassAliases(tokens []token) map[string]string {
	aliases := map[string]string{}
	for pos := 0; pos+1 < len(tokens); pos++ {
		if !equalName(tokens[pos], "use") || tokens[pos+1].kind != tokenName {
			continue
		}

		class := strings.TrimPrefix(tokens[pos+1].value, "\\")
		if !strings.HasPrefix(strings.ToLower(class), "slim\\") {
			continue
		}

		alias := shortPHPName(class)
		hasAlias := pos+3 < len(tokens) &&
			equalName(tokens[pos+2], "as") &&
			tokens[pos+3].kind == tokenName
		if hasAlias {
			alias = tokens[pos+3].value
		}

		aliases[alias] = class
	}
	return aliases
}

func isSlimRouterType(name string, aliases map[string]string) bool {
	return isSlimApp(name, aliases) ||
		strings.EqualFold(slimClass(name, aliases), "Slim\\Routing\\RouteCollectorProxy")
}

func isSlimApp(name string, aliases map[string]string) bool {
	return strings.EqualFold(slimClass(name, aliases), "Slim\\App")
}

func isSlimAppFactory(name string, aliases map[string]string) bool {
	return strings.EqualFold(slimClass(name, aliases), "Slim\\Factory\\AppFactory")
}

func slimClass(name string, aliases map[string]string) string {
	name = strings.TrimPrefix(name, "\\")
	// PHP class names and imported aliases are case-insensitive.
	for alias, resolved := range aliases {
		if strings.EqualFold(alias, name) {
			return resolved
		}
	}

	return name
}

func nextNamedToken(tokens []token, start, end int, name string) int {
	for pos := start; pos < end; pos++ {
		if equalName(tokens[pos], name) {
			return pos
		}
	}

	return -1
}
