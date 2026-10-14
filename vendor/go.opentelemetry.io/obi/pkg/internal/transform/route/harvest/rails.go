// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxRailsFileBytes  int64 = 2 * 1024 * 1024
	maxRailsRouteFiles       = 256
)

var (
	railsDraw          = regexp.MustCompile(`^draw\b\s*\(?\s*(.*)$`)
	railsDeclaration   = regexp.MustCompile(`^(get|post|put|patch|delete|head|options|match|resources|resource|namespace|scope)\b\s*\(?\s*(.*)$`)
	railsLiteral       = regexp.MustCompile(`^(?:'([^'\\]*)'|"([^"\\#]*)"|:([A-Za-z_][A-Za-z_0-9]*))(\s*(?:,|\)|=>|do\b|$))`)
	railsAPIOnly       = regexp.MustCompile(`^config\.api_only\s*=\s*(true|false)\s*$`)
	railsPathOption    = regexp.MustCompile(`(?:^|,\s*)(?:path:|:path\s*=>)\s*(.*)$`)
	railsActionsOption = regexp.MustCompile(`(?:^|,\s*)(?:(only|except):|:(only|except)\s*=>)\s*(\[[^\]]*\]|%i\[[^\]]*\]|[^,)]*)`)
	railsParamOption   = regexp.MustCompile(`(?:^|,\s*)(?:param:|:param\s*=>)\s*(.*)$`)

	railsDefaultResourceActions = [...]string{"index", "create", "show", "update", "destroy", "new", "edit"}
	railsAPIOnlyResourceActions = [...]string{"index", "create", "show", "update", "destroy"}
)

type railsRouteScanner struct {
	resourceActions []string
}

func newRailsRouteScanner() railsRouteScanner {
	return railsRouteScanner{resourceActions: railsDefaultResourceActions[:]}
}

func newRailsAPIRouteScanner() railsRouteScanner {
	return railsRouteScanner{resourceActions: railsAPIOnlyResourceActions[:]}
}

// ExtractRubyRoutes reads Rails route declarations without executing application
// code. Fragments preserve useful paths even when Ruby's dynamic DSL prevents
// resolving the surrounding scope statically.
func ExtractRubyRoutes(ctx context.Context, pid app.PID) (*RouteHarvesterResult, error) {
	cwd, err := cwdForPID(pid)
	if err != nil {
		return nil, fmt.Errorf("finding Ruby working directory: %w", err)
	}
	return extractRailsRoutes(ctx, rootDirForPID(pid), cwd)
}

func extractRailsRoutes(ctx context.Context, root, cwd string) (*RouteHarvesterResult, error) {
	result := &RouteHarvesterResult{Kind: PartialRoutes}
	root, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return result, nil
	}
	dir, ok := langtools.ResolveProcessPath(root, "/", cwd)
	if !ok {
		return result, nil
	}
	// A server may start below the app root; use the nearest config/routes.rb.
	err := langtools.WalkParentDirectories(dir, root, func(dir string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		relative, err := filepath.Rel(root, filepath.Join(dir, "config", "routes.rb"))
		if err != nil {
			return true, err
		}
		path, ok := langtools.ResolveProcessPath(root, "/", relative)
		if !ok {
			return false, nil
		}
		result.Routes, err = scanRailsRouteFiles(ctx, root, path)
		return true, err
	})
	return result, err
}

// Rails resolves every draw relative to config/routes, including nested draws.
// Follow references only: other files in that directory may not be loaded by Rails.
func scanRailsRouteFiles(ctx context.Context, root, mainPath string) ([]string, error) {
	apiOnly, err := readRailsAPIOnly(ctx, filepath.Join(filepath.Dir(mainPath), "application.rb"))
	if err != nil {
		return nil, err
	}
	scanner := newRailsRouteScanner()
	if apiOnly {
		scanner = newRailsAPIRouteScanner()
	}
	routesDir := filepath.Join(filepath.Dir(mainPath), "routes")
	pending := []string{mainPath}
	seen := map[string]struct{}{mainPath: {}}
	var routes []string
	for index := 0; index < len(pending); index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fragments, draws, err := scanner.readRouteFile(ctx, pending[index])
		if err != nil {
			return nil, err
		}
		routes = append(routes, fragments...)
		for _, name := range draws {
			if len(seen) >= maxRailsRouteFiles {
				break
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !filepath.IsLocal(name) || strings.Contains(name, "\\") {
				continue
			}
			// Do not allow draw references to escape the application's routes directory.
			if slices.Contains(strings.Split(name, "/"), "..") {
				continue
			}
			relative, err := filepath.Rel(root, filepath.Join(routesDir, name+".rb"))
			if err != nil {
				return nil, err
			}
			path, ok := langtools.ResolveProcessPath(root, "/", relative)
			if !ok {
				continue
			}
			withinRoutes, err := filepath.Rel(routesDir, path)
			if err != nil || !filepath.IsLocal(withinRoutes) {
				continue
			}
			if _, visited := seen[path]; visited {
				continue
			}
			seen[path] = struct{}{}
			pending = append(pending, path)
		}
	}
	slices.Sort(routes)
	routes = slices.Compact(routes)
	sortRouteFragments(routes)
	return routes, nil
}

func readRailsAPIOnly(ctx context.Context, path string) (bool, error) {
	file, _ := langtools.OpenMetadataFile(path, maxRailsFileBytes)
	if file == nil {
		return false, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(io.LimitReader(file, maxRailsFileBytes))
	scanner.Buffer(nil, int(maxRailsFileBytes))
	inComment := false
	apiOnly := false
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "=begin") {
			inComment = true
		}
		if inComment {
			if strings.HasPrefix(line, "=end") {
				inComment = false
			}
			continue
		}
		if match := railsAPIOnly.FindStringSubmatch(stripRailsComment(line)); match != nil {
			apiOnly = match[1] == "true"
		}
	}
	return apiOnly, scanner.Err()
}

func (s railsRouteScanner) readRouteFile(ctx context.Context, path string) ([]string, []string, error) {
	file, _ := langtools.OpenMetadataFile(path, maxRailsFileBytes)
	if file == nil {
		return nil, nil, nil
	}
	defer file.Close()
	return s.scanRoutes(ctx, io.LimitReader(file, maxRailsFileBytes))
}

func scanRailsRoutes(ctx context.Context, reader io.Reader) ([]string, []string, error) {
	scanner := newRailsRouteScanner()
	return scanner.scanRoutes(ctx, reader)
}

func (s railsRouteScanner) scanRoutes(ctx context.Context, reader io.Reader) ([]string, []string, error) {
	var routes, draws []string
	scanner := bufio.NewScanner(reader)
	// bufio.Scanner defaults to a 64KiB token limit; match it to the read budget
	// above so a single long line doesn't abort the scan with ErrTooLong.
	scanner.Buffer(nil, int(maxRailsFileBytes))
	inComment := false
	var pending string
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "=begin") {
			inComment = true
		}
		if inComment {
			if strings.HasPrefix(line, "=end") {
				inComment = false
			}
			continue
		}
		// Strip comments outside string literals, leaving controller#action intact.
		line = stripRailsComment(line)
		if line == "" {
			continue
		}
		if pending != "" {
			line = pending + " " + line
		}
		if strings.HasSuffix(line, ",") {
			pending = line
			continue
		}
		pending = ""
		if draw := railsDraw.FindStringSubmatch(line); draw != nil {
			if name, ok := railsLiteralValue(draw[1]); ok && name != "" {
				draws = append(draws, name)
			}
			continue
		}
		if line == "root" || strings.HasPrefix(line, "root ") || strings.HasPrefix(line, "root(") {
			routes = append(routes, "/")
			continue
		}
		declaration := railsDeclaration.FindStringSubmatch(line)
		if declaration == nil {
			continue
		}
		kind, args := declaration[1], declaration[2]
		paths, ok := railsLiteralValues(args)
		if override := railsPathOption.FindStringSubmatch(args); override != nil {
			path, valid := railsLiteralValue(override[1])
			paths, ok = []string{path}, valid
		}
		if !ok {
			continue
		}
		param := "id"
		if kind == "resources" || kind == "resource" {
			if option := railsParamOption.FindStringSubmatch(args); option != nil {
				var ok bool
				param, ok = railsLiteralValue(option[1])
				if !ok || !validRailsParam(param) {
					continue
				}
			}
		}
		for _, path := range paths {
			if path == "" {
				continue
			}
			path = ensureLeadingSlash(strings.Trim(path, "/"))
			// Optional segments and globs need matcher semantics beyond literal fragments.
			if strings.ContainsAny(path, "()*") {
				continue
			}
			// Scope prefixes stay separate; the partial matcher combines them with child routes.
			if kind != "resources" && kind != "resource" {
				routes = append(routes, path)
				break
			}
			routes = append(routes, s.resourceRoutes(kind, path, param, args)...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	slices.Sort(routes)
	routes = slices.Compact(routes)
	sortRouteFragments(routes)
	return routes, draws, nil
}

// REST actions can share a path. Singular resources have no collection index or ID segment.
func (s railsRouteScanner) resourceRoutes(kind, path, param, args string) []string {
	var selectedActions []string
	var selectionKind string
	if option := railsActionsOption.FindStringSubmatch(args); option != nil {
		var ok bool
		selectedActions, ok = railsActions(strings.TrimSpace(option[3]))
		if !ok {
			return nil
		}
		selectionKind = option[1]
		if selectionKind == "" {
			selectionKind = option[2]
		}
	}
	var routes []string
	for _, action := range s.resourceActions {
		if selectionKind != "" {
			included := slices.Contains(selectedActions, action)
			if selectionKind == "only" && !included {
				continue
			}
			if selectionKind == "except" && included {
				continue
			}
		}
		switch action {
		case "index", "create":
			if action != "index" || kind == "resources" {
				routes = append(routes, path)
			}
		case "new":
			routes = append(routes, path+"/new")
		case "show", "update", "destroy", "edit":
			member := path
			if kind == "resources" {
				member += "/:" + param
			}
			if action == "edit" {
				member += "/edit"
			}
			routes = append(routes, member)
		}
	}
	return routes
}

func railsActions(value string) ([]string, bool) {
	if strings.HasPrefix(value, "%i[") && strings.HasSuffix(value, "]") {
		return strings.Fields(value[3 : len(value)-1]), true
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSpace(value[1 : len(value)-1])
		if value == "" {
			return nil, true
		}
		var actions []string
		for item := range strings.SplitSeq(value, ",") {
			action, ok := railsLiteralValue(strings.TrimSpace(item))
			if !ok {
				return nil, false
			}
			actions = append(actions, action)
		}
		return actions, true
	}
	action, ok := railsLiteralValue(value)
	return []string{action}, ok
}

// Require an argument boundary so expressions like "/users" + suffix are not
// mistaken for complete literal paths.
func railsLiteralValue(value string) (string, bool) {
	match := railsLiteral.FindStringSubmatch(value)
	if match == nil {
		return "", false
	}
	return match[1] + match[2] + match[3], true
}

func railsLiteralValues(value string) ([]string, bool) {
	var values []string
	for {
		value = strings.TrimSpace(value)
		match := railsLiteral.FindStringSubmatch(value)
		if match == nil {
			break
		}
		// Hash-rocket keys are options (`:only => :show`), not resource names.
		delimiter := strings.TrimSpace(match[4])
		if delimiter == "=>" {
			break
		}
		values = append(values, match[1]+match[2]+match[3])
		if delimiter != "," {
			break
		}
		value = value[len(match[0]):]
	}
	return values, len(values) > 0
}

func validRailsParam(param string) bool {
	if param == "" {
		return false
	}
	for _, char := range param {
		if char != '_' && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func stripRailsComment(line string) string {
	var quote rune
	escaped := false
	for pos, char := range line {
		if escaped {
			escaped = false
			continue
		}
		switch {
		case quote != 0:
			switch char {
			case '\\':
				escaped = true
			case quote:
				quote = 0
			}
		case char == '\'' || char == '"':
			quote = char
		case char == '#':
			return strings.TrimSpace(line[:pos])
		}
	}
	return line
}
