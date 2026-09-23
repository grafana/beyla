// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

type djangoRoute struct {
	path          string
	listName      string
	includeList   string
	includeModule string
	admin         bool
	skipExpansion bool
}

var djangoAdminRoutes = []string{
	"",
	"login/",
	"logout/",
	"password_change/",
	"password_change/done/",
	"autocomplete/",
	"jsi18n/",
	"r/<path:content_type_id>/<path:object_id>/",
	"<app_label>/",
	"<app_label>/<model_name>/",
	"<app_label>/<model_name>/add/",
	"<app_label>/<model_name>/<path:object_id>/history/",
	"<app_label>/<model_name>/<path:object_id>/delete/",
	"<app_label>/<model_name>/<path:object_id>/change/",
	"<app_label>/<model_name>/<path:object_id>/",
}

var djangoPathImportPattern = regexp.MustCompile(
	`^from\s+django\.urls\s+import\s+(?:\(\s*)?(?:\w+(?:\s+as\s+\w+)?\s*,\s*)*(?:re_)?path\s*(?:,|\)|$|#)`,
)

var djangoImportStart = regexp.MustCompile(`^from\s+django\.urls\s+import\s*\(`)

var djangoFromImportAliasPattern = regexp.MustCompile(
	`^from\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+import\s+([A-Za-z_]\w*)\s+as\s+([A-Za-z_]\w*)\s*(?:#.*)?$`,
)

var djangoImportAliasPattern = regexp.MustCompile(
	`^import\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+as\s+([A-Za-z_]\w*)\s*(?:#.*)?$`,
)

var djangoPathStart = regexp.MustCompile(`\b(?:re_)?path\s*\(`)

var djangoListAssignmentPattern = regexp.MustCompile(`^([A-Za-z_]\w*)\s*(\+?=)\s*(.*)$`)

var djangoListNamePattern = regexp.MustCompile(`^[A-Za-z_]\w*`)

type djangoList struct {
	routes []djangoRoute
}

type djangoAssignment struct {
	name     string
	append   bool
	operands []string
}

// djangoListAssignment preserves operand order and the assignment operator.
func djangoListAssignment(stmt string) (djangoAssignment, bool) {
	match := djangoListAssignmentPattern.FindStringSubmatch(stmt)
	if match == nil {
		return djangoAssignment{}, false
	}

	expr := strings.TrimSpace(match[3])
	assignment := djangoAssignment{name: match[1], append: match[2] == "+="}
	for {
		operand := expr
		var end int
		if strings.HasPrefix(expr, "[") {
			end = djangoDelimitedEnd(expr, 0)
		} else if wrapper := djangoI18nStart.FindStringIndex(expr); wrapper != nil && wrapper[0] == 0 {
			end = djangoDelimitedEnd(expr, wrapper[1]-1)
		} else {
			name := djangoListNamePattern.FindString(expr)
			end = len(name) - 1
		}
		if end < 0 {
			return djangoAssignment{}, false
		}
		assignment.operands = append(assignment.operands, operand[:end+1])
		expr = strings.TrimSpace(expr[end+1:])

		if expr == "" || strings.HasPrefix(expr, "#") {
			return assignment, true
		}
		if expr[0] != '+' {
			return djangoAssignment{}, false
		}
		expr = strings.TrimSpace(expr[1:])
	}
}

func applyDjangoAssignment(lists map[string]*djangoList, assignment djangoAssignment, aliases map[string]string) {
	// A direct alias shares the list object, including subsequent appends.
	if !assignment.append && len(assignment.operands) == 1 {
		if source, ok := lists[assignment.operands[0]]; ok {
			lists[assignment.name] = source
			return
		}
	}

	// Collect known RHS routes before mutating the destination, including self-appends.
	var routes []djangoRoute
	for _, operand := range assignment.operands {
		if strings.HasPrefix(operand, "[") || djangoI18nStart.MatchString(operand) {
			routes = append(routes, scanDjango(operand, aliases)...)
		} else {
			source, ok := lists[operand]
			if !ok {
				continue
			}
			routes = append(routes, source.routes...)
		}
	}
	if assignment.append {
		target, ok := lists[assignment.name]
		if !ok {
			target = &djangoList{}
			lists[assignment.name] = target
		}
		target.routes = append(target.routes, routes...)
	} else {
		lists[assignment.name] = &djangoList{routes: routes}
	}
}

var djangoI18nStart = regexp.MustCompile(`\bi18n_patterns\s*\(`)

var djangoI18nUnprefixedDefault = regexp.MustCompile(
	`(?:^|,)\s*prefix_default_language\s*=\s*False\s*,?\s*$`,
)

var djangoPathPattern = regexp.MustCompile(
	`\b(?:re_)?path\s*\(\s*(?:route\s*=\s*)?` + pyLit +
		`\s*,\s*(?:view\s*=\s*)?(?:include\s*\(\s*(?:\(\s*)?` + pyLit + `|(admin\.site\.urls)\b` +
		`|(include)\s*\(\s*(?:\(\s*)?(?:([A-Za-z_]\w*)\s*[,)])?)?`,
)

// djangoRegexRoute parses a supported endpoint or include re_path expression into a route template.
// For example, ^articles/(?P<year>[0-9]{4})/$ becomes articles/<year>/.
func djangoRegexRoute(pattern string, endpoint bool) (string, bool) {
	expr, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return "", false
	}
	begin, end := djangoRegexBoundaries(expr)
	if endpoint {
		// Django uses fullmatch for endpoint patterns whose source ends in '$'.
		if !strings.HasSuffix(pattern, "$") {
			return "", false
		}
	} else if !begin || end {
		// Includes must match at the current prefix and leave a suffix for child routes.
		return "", false
	}
	return djangoRegexExprRoute(expr)
}

func djangoRegexBoundaries(expr *syntax.Regexp) (bool, bool) {
	first, last := expr, expr
	if expr.Op == syntax.OpConcat && len(expr.Sub) > 0 {
		first = expr.Sub[0]
		last = expr.Sub[len(expr.Sub)-1]
	}
	return first.Op == syntax.OpBeginText, last.Op == syntax.OpEndText
}

// djangoRegexExprRoute converts a parsed regex into a route template.
// Example: ^articles/(?P<year>[0-9]{4})/$ returns ("articles/<year>/", true).
func djangoRegexExprRoute(expr *syntax.Regexp) (string, bool) {
	// The route matcher compares literal text case-sensitively.
	if expr.Flags&syntax.FoldCase != 0 {
		return "", false
	}
	switch expr.Op {
	case syntax.OpBeginText, syntax.OpEndText:
		// Anchors describe matching boundaries and contribute no path text.
		return "", true
	case syntax.OpLiteral:
		return string(expr.Rune), true
	case syntax.OpCapture:
		body := expr.Sub[0]
		// Both + and positive exact counts such as {4} produce non-empty parameters.
		fixedCount := body.Op == syntax.OpRepeat && body.Min > 0 && body.Min == body.Max
		if expr.Name == "" || (body.Op != syntax.OpPlus && !fixedCount) || body.Sub[0].Op != syntax.OpCharClass {
			return "", false
		}
		class := body.Sub[0]
		// Rune stores inclusive [low, high] pairs. A single-segment parameter
		// requires every range to exclude the path separator.
		for i := 0; i < len(class.Rune); i += 2 {
			if class.Rune[i] <= '/' && '/' <= class.Rune[i+1] {
				return "", false
			}
		}
		return "<" + expr.Name + ">", true
	case syntax.OpConcat:
		// A route such as articles/<year>/ is a sequence of literals and captures.
		// Every child must be supported for the complete template to be usable.
		var route strings.Builder
		for i, part := range expr.Sub {
			// Captures must occupy a whole segment for the route matcher.
			if part.Op == syntax.OpCapture {
				// The preceding text must end at a slash or be empty.
				// A prefix such as page(?P<num>[0-9]+) shares the capture's segment.
				if route.Len() > 0 && !strings.HasSuffix(route.String(), "/") {
					return "", false
				}
				if i+1 < len(expr.Sub) {
					next := expr.Sub[i+1]
					// A following slash or end anchor closes the segment.
					// Text such as (?P<id>[0-9]+)\.html remains in the same segment.
					if next.Op != syntax.OpEndText &&
						(next.Op != syntax.OpLiteral || !strings.HasPrefix(string(next.Rune), "/")) {
						return "", false
					}
				}
			}
			text, ok := djangoRegexExprRoute(part)
			if !ok {
				return "", false
			}
			route.WriteString(text)
		}
		return route.String(), true
	}
	return "", false
}

// djangoDelimitedEnd finds the matching delimiter for a call or list starting at open.
// Delimiters inside quoted strings are part of the argument value.
func djangoDelimitedEnd(stmt string, open int) int {
	opening, closing := stmt[open], byte(')')
	if opening == '[' {
		closing = ']'
	}
	depth := 0
	var quote byte
	for i := open; i < len(stmt); i++ {
		if quote != 0 {
			switch stmt[i] {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch stmt[i] {
		case '\'', '"':
			quote = stmt[i]
		case opening:
			depth++
		case closing:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func scanDjango(stmt string, aliases map[string]string) []djangoRoute {
	var routes []djangoRoute
	for {
		wrapper := djangoI18nStart.FindStringIndex(stmt)
		if wrapper == nil {
			return append(routes, scanDjangoPaths(stmt, aliases)...)
		}
		routes = append(routes, scanDjangoPaths(stmt[:wrapper[0]], aliases)...)
		end := djangoDelimitedEnd(stmt, wrapper[1]-1)
		if end < 0 {
			return routes
		}
		// Prefix only declarations inside the wrapper, including mounts for child modules.
		localized := scanDjangoPaths(stmt[wrapper[1]:end], aliases)
		if djangoI18nUnprefixedDefault.MatchString(stmt[wrapper[1]:end]) {
			// The default language also serves these routes without a language prefix.
			routes = append(routes, localized...)
		}
		for i := range localized {
			localized[i].path = "<language>/" + localized[i].path
		}
		routes = append(routes, localized...)
		stmt = stmt[end+1:]
	}
}

func scanDjangoPaths(stmt string, aliases map[string]string) []djangoRoute {
	var routes []djangoRoute
	for _, match := range djangoPathPattern.FindAllStringSubmatch(stmt, -1) {
		route := match[1] // Double-quoted route.
		if route == "" {
			route = match[2] // Single-quoted route.
		}

		includeModule := match[3] // Double-quoted include module.
		if includeModule == "" {
			includeModule = match[4] // Single-quoted include module.
		}

		var includeList string
		if match[6] != "" { // Non-literal include() call.
			includeModule = aliases[match[7]] // Imported module alias.
			if includeModule == "" {
				includeList = match[7]
				if includeList == "" {
					// An unresolved include is a mount whose endpoints are unknown.
					continue
				}
			}
		}
		admin := match[5] != ""
		skipExpansion := false
		if strings.HasPrefix(match[0], "re_path") {
			endpoint := includeModule == "" && includeList == "" && !admin
			converted, ok := djangoRegexRoute(route, endpoint)
			if !ok {
				if includeModule == "" {
					continue
				}
				// Keep the module reference so its file is not inferred as an unmounted root.
				skipExpansion = true
			} else {
				route = converted
			}
		}

		// The resolver expands includes and admin.site.urls; ordinary views are endpoints.
		routes = append(routes, djangoRoute{
			path:          route,
			includeList:   includeList,
			includeModule: includeModule,
			admin:         admin,
			skipExpansion: skipExpansion,
		})
	}
	return routes
}

// indexDjangoModules maps dotted include targets, such as "checkout.urls", to
// scanned Python files relative to the application root.
func indexDjangoModules(root string, files map[string][]djangoRoute) map[string]string {
	modules := make(map[string]string, len(files))
	for file := range files {
		if !langtools.PathWithinBoundary(root, file) {
			continue
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			continue
		}
		module := strings.TrimSuffix(filepath.ToSlash(rel), ".py")
		module = strings.ReplaceAll(module, "/", ".")
		if module == "__init__" {
			continue
		}
		if packageModule, ok := strings.CutSuffix(module, ".__init__"); ok {
			modules[packageModule] = file
			continue
		}
		if _, exists := modules[module]; !exists {
			modules[module] = file
		}
	}
	return modules
}

// djangoRootFiles selects starting points for route expansion. Included files
// contribute routes through their parent prefixes.
func djangoRootFiles(files map[string][]djangoRoute, modules map[string]string) []string {
	included := map[string]struct{}{}
	for _, declarations := range files {
		for _, declaration := range declarations {
			if file, ok := modules[declaration.includeModule]; ok {
				included[file] = struct{}{}
			}
		}
	}

	var roots []string
	for file, declarations := range files {
		if _, ok := included[file]; !ok && len(declarations) > 0 {
			roots = append(roots, file)
		}
	}
	sort.Strings(roots)
	return roots
}

// resolveDjangoRoutes expands module and named-list includes from inferred root
// files. Each visit carries the mount prefix accumulated from its parents;
// endpoint paths are published with that prefix and a leading slash.
func resolveDjangoRoutes(root string, files map[string][]djangoRoute, routes map[string]struct{}) {
	const maxIncludeDepth = 32

	modules := indexDjangoModules(root, files)
	// A file can contain several lists that include each other, so recursion
	// tracking identifies both the file and the list being expanded.
	type listKey struct {
		file string
		name string
	}
	active := map[listKey]bool{}
	var visit func(file, listName, prefix string)
	visit = func(file, listName, prefix string) {
		key := listKey{file: file, name: listName}
		if active[key] || len(active) >= maxIncludeDepth {
			return
		}
		// Track the current chain so another mount can visit this file again.
		active[key] = true
		defer delete(active, key)

		for _, declaration := range files[file] {
			// Select this list's routes. Unassigned declarations, including those
			// from i18n_patterns(), are treated as part of the file's urlpatterns.
			if declaration.listName != listName &&
				(declaration.listName != "" || listName != "urlpatterns") {
				continue
			}
			if declaration.skipExpansion {
				continue
			}
			if declaration.includeList != "" {
				// A named-list include stays in this file and adds its mount prefix.
				visit(file, declaration.includeList, prefix+declaration.path)
				continue
			}
			if declaration.includeModule != "" {
				// A module include starts at the child file's urlpatterns.
				if child, ok := modules[declaration.includeModule]; ok {
					visit(child, "urlpatterns", prefix+declaration.path)
				}
				continue
			}
			if declaration.admin {
				for _, adminRoute := range djangoAdminRoutes {
					routes["/"+prefix+declaration.path+adminRoute] = struct{}{}
				}
				continue
			}
			routes["/"+prefix+declaration.path] = struct{}{}
		}
	}
	for _, file := range djangoRootFiles(files, modules) {
		// Included files are reached through their mounts rather than as roots.
		visit(file, "urlpatterns", "")
	}
}
