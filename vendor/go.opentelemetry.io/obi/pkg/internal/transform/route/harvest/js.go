// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

// /root is purposefully missing, since we need it to star the file walk
// we skip later any root directories we find that don't match our original
// path
var skipDirs = map[string]string{
	// Linux root file system
	"bin":        "Essential command binaries",
	"boot":       "Boot loader files",
	"dev":        "Device files",
	"etc":        "System configuration files",
	"home":       "User home directories",
	"lib":        "Essential shared libraries",
	"lib64":      "64-bit libraries",
	"media":      "Removable media mount points",
	"mnt":        "Temporary mount points",
	"opt":        "Optional software packages",
	"proc":       "Process and kernel information",
	"run":        "Runtime data",
	"sbin":       "System binaries",
	"srv":        "Service data",
	"sys":        "Kernel and device information",
	"tmp":        "Temporary files",
	"usr":        "User programs and data",
	"var":        "Variable data",
	"lost+found": "Recovered files",
	"snap":       "Snap packages",
	"flatpak":    "Flatpak packages",
	"ostree":     "Used by rpm-ostree/Fedora Silverblue for atomic updates",
	"sysroot":    "Used in some immutable/atomic variants as the actual root filesystem",
	// Node specific
	"node_modules": "Standard node modules",
	".npm":         "npm build cache",
	".git":         "git source control",
	"dist":         "distribution directories",
	"build":        "build directories",
	".next":        "Next.js output/metadata directory",
}

// RoutePattern represents an extracted HTTP route
type RoutePattern struct {
	Method  string
	Path    string
	File    string
	Line    int
	Handler string
}

// FrameworkPatterns holds regex patterns for different Node.js frameworks
type FrameworkPatterns struct {
	// Express, Koa, Fastify short: app.get('/path', handler), router.post('/path', handler)
	Typical *regexp.Regexp
	// Express route chaining: .route('/path').get(handler).post(handler)
	ExpressRoute *regexp.Regexp
	// Fastify: fastify.get('/path', handler), fastify.route({ method: 'GET', url: '/path' })
	FastifyShort *regexp.Regexp
	FastifyRoute *regexp.Regexp
	// Koa Router: router.get('/path', handler)
	KoaRouter *regexp.Regexp
	// Hapi: server.route({ method: 'GET', path: '/path' })
	Hapi *regexp.Regexp
	// Restify: server.get('/path', handler)
	Restify *regexp.Regexp
	// NestJS decorators: @Get('/path'), @Post('/path')
	NestJS *regexp.Regexp
	// HTTPDispatcher: dispatcher.onGet('/path', ...), dispatcher.onPost(/^\/ratings\/[0-9]*/, ...)
	HTTPDispatcher *regexp.Regexp
	// Fallback
	Fallback *regexp.Regexp

	// Path Cleanup regexes
	RegexPattern         *regexp.Regexp
	MultipleSlashPattern *regexp.Regexp
	CleanID              *regexp.Regexp
	// ValidPathChars matches valid URL path characters per RFC 3986
	// Includes: unreserved (A-Za-z0-9-._~)
	ValidPathChars *regexp.Regexp
}

// nextRoutesManifest is a partial representation of .next/routes-manifest.json.
type nextRoutesManifest struct {
	DynamicRoutes []struct {
		Page string `json:"page"`
	} `json:"dynamicRoutes"`
	StaticRoutes []struct {
		Page string `json:"page"`
	} `json:"staticRoutes"`
}

func newFrameworkPatterns() *FrameworkPatterns {
	return &FrameworkPatterns{
		// Matches: app.get('/users/:id', ...), router.post("/items", ...)
		Typical: regexp.MustCompile(`\.(get|post|put|patch|delete|head|options|all)\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]`),

		// Matches: .route('/path')
		ExpressRoute: regexp.MustCompile(`\.route\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]\s*\)`),

		// Matches: fastify.route({ method: 'GET', url: '/path' })
		FastifyRoute: regexp.MustCompile(`\.route\s*\(\s*\{[^}]*method:\s*['"\x60](\w+)['"\x60][^}]*url:\s*['"\x60]([^'"\x60]+)['"\x60]`),

		// Matches: server.route({ method: 'GET', path: '/users/{id}' })
		Hapi: regexp.MustCompile(`\.route\s*\(\s*\{[^}]*method:\s*['"](\w+)['"][^}]*path:\s*['"\x60]([^'"\x60]+)['"\x60]`),

		// Matches: server.get('/path', ...), server.post('/users/:id', ...)
		Restify: regexp.MustCompile(`\.(get|post|put|patch|del|head|opts)\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]`),

		// Matches: @Get('/users/:id'), @Post('/items')
		NestJS: regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|Options|Head|All)\s*\(\s*['"\x60]([^'"\x60]*?)['"\x60]\s*\)`),

		// Matches: dispatcher.onGet('/path', ...), dispatcher.onPost(/^\/ratings\/[0-9]*/, ...)
		// Supports both string literals and regex literals
		HTTPDispatcher: regexp.MustCompile(`\.on(Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(\s*(?:['"\x60]([^'"\x60]+)['"\x60]|/((?:[^\\,]|\\.)+))`),

		// Fallback (e.g. NextJS)
		Fallback: regexp.MustCompile(`['"\x60](/[^'"\x60]+)['"\x60]`),

		// Cleanup
		RegexPattern:         regexp.MustCompile(`[\\^$]`),
		MultipleSlashPattern: regexp.MustCompile(`//+`),
		ValidPathChars:       regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`),
		CleanID:              regexp.MustCompile(`[^A-Za-z0-9\-._]+`),
	}
}

type RouteExtractor struct {
	log      *slog.Logger
	patterns *FrameworkPatterns
	routes   []RoutePattern
}

func NewRouteExtractor() *RouteExtractor {
	return &RouteExtractor{
		patterns: newFrameworkPatterns(),
		routes:   []RoutePattern{},
		log:      slog.With("component", "route.harvester.js"),
	}
}

func (e *RouteExtractor) expressPendingRoute(filePath, line string, lineNum int) bool {
	if matches := e.patterns.ExpressRoute.FindStringSubmatch(line); len(matches) > 1 {
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   matches[1],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}
	return false
}

func (e *RouteExtractor) handleTypicalRoute(filePath, line string, lineNum int) bool {
	if matches := e.patterns.Typical.FindStringSubmatch(line); len(matches) > 2 {
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   matches[2],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}
	return false
}

func (e *RouteExtractor) handleFastifyRoute(filePath, line string, lineNum int) bool {
	if matches := e.patterns.FastifyRoute.FindStringSubmatch(line); len(matches) > 2 {
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   matches[2],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}

	return false
}

func (e *RouteExtractor) handleHapi(filePath, line string, lineNum int) bool {
	if matches := e.patterns.Hapi.FindStringSubmatch(line); len(matches) > 2 {
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   matches[2],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}
	return false
}

func (e *RouteExtractor) handleRestify(filePath, line string, lineNum int) bool {
	if matches := e.patterns.Restify.FindStringSubmatch(line); len(matches) > 2 {
		method := matches[1]
		// Normalize restify methods: del -> DELETE, opts -> OPTIONS
		switch method {
		case "del":
			method = "delete"
		case "opts":
			method = "options"
		}
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(method),
			Path:   matches[2],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}
	return false
}

func (e *RouteExtractor) handleNestJS(filePath, line string, lineNum int) bool {
	if matches := e.patterns.NestJS.FindStringSubmatch(line); len(matches) > 2 {
		path := matches[2]
		// NestJS defaults to '/' if no path specified
		if path == "" {
			path = "/"
		}
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   path,
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}

	return false
}

func (e *RouteExtractor) handleHTTPDispatcher(filePath, line string, lineNum int) bool {
	if matches := e.patterns.HTTPDispatcher.FindStringSubmatch(line); len(matches) > 2 {
		method := strings.ToUpper(matches[1])
		// Extract path - either from string literal (group 2) or regex literal (group 3)
		path := matches[2]
		if path == "" && len(matches) > 3 {
			// It's a regex literal, wrap it to indicate regex
			path = "/" + matches[3] + "/"
		}
		e.routes = append(e.routes, RoutePattern{
			Method: method,
			Path:   path,
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}

	return false
}

func (e *RouteExtractor) handleFallback(filePath, line string, lineNum int) bool {
	if matches := e.patterns.Fallback.FindStringSubmatch(line); len(matches) > 0 {
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   matches[0],
			File:   filePath,
			Line:   lineNum,
		})
		return true
	}

	return false
}

// extractNextJSRoutesFromManifest tries to read a Next.js routes-manifest.json
// under the given directory. It adds any routes found to the extractor.
func (e *RouteExtractor) extractNextJSRoutesFromManifest(dir string) error {
	manifestPath := filepath.Join(dir, ".next", "routes-manifest.json")

	f, err := os.Open(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Not a Next.js app or no build output yet; nothing to do.
			return nil
		}
		return fmt.Errorf("open next.js routes-manifest %q: %w", manifestPath, err)
	}
	defer f.Close()

	var manifest nextRoutesManifest
	if err := json.NewDecoder(f).Decode(&manifest); err != nil {
		// Malformed JSON or incompatible format – return an error.
		return fmt.Errorf("decode next.js routes-manifest %q: %w", manifestPath, err)
	}

	// Convert Next.js params [id], [...slug] -> :id, :slug
	paramRe := regexp.MustCompile(`\[(\.\.\.)?([^\]]+)\]`)

	normalizePage := func(page string) string {
		return paramRe.ReplaceAllStringFunc(page, func(m string) string {
			sub := paramRe.FindStringSubmatch(m)
			if len(sub) < 3 {
				return m
			}
			// sub[1] is "..." or "", sub[2] is the param name
			name := sub[2]
			return ":" + name
		})
	}

	for _, r := range manifest.StaticRoutes {
		path := normalizePage(r.Page)
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   path,
			File:   manifestPath,
			Line:   0, // not line-based
		})
	}

	for _, r := range manifest.DynamicRoutes {
		path := normalizePage(r.Page)
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   path,
			File:   manifestPath,
			Line:   0,
		})
	}

	return nil
}

func (e *RouteExtractor) scanFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	var line string
	var save string

	for scanner.Scan() {
		lineNum++
		line = scanner.Text()
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.Contains(line, ";") {
			save = ""
		}
		if save != "" {
			line = save + "\n" + line
			save = ""
		}
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || trimmed == "" {
			continue
		}

		// Check for .route() pattern for chained handlers
		if e.expressPendingRoute(filePath, line, lineNum) {
			continue
		}

		// Express/Router, Koa, Fastify Short patterns
		if e.handleTypicalRoute(filePath, line, lineNum) {
			continue
		}

		// Fastify route object
		if e.handleFastifyRoute(filePath, line, lineNum) {
			continue
		}

		// Hapi
		if e.handleHapi(filePath, line, lineNum) {
			continue
		}

		// Restify
		if e.handleRestify(filePath, line, lineNum) {
			continue
		}

		// NestJS decorators
		if e.handleNestJS(filePath, line, lineNum) {
			continue
		}

		// HttpDispatcher
		if e.handleHTTPDispatcher(filePath, line, lineNum) {
			continue
		}

		// Fallback when none matches
		if e.handleFallback(filePath, line, lineNum) {
			continue
		}

		save = line
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (e *RouteExtractor) ScanDirectory(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		e.log.Debug("scanning", "path", path, "name", info.Name())

		// Skip node_modules, .git, and other common dirs
		if info.IsDir() {
			name := info.Name()
			// skip the nested root directory in the original /proc/<pid>/root
			if name == "root" && path != root {
				return filepath.SkipDir
			}

			// check if the list of directories hits any known dirs for nodejs or linux
			// we should be avoiding
			if _, ok := skipDirs[name]; ok {
				return filepath.SkipDir
			}
			return nil
		}

		// Only scan JS/TS file types
		ext := filepath.Ext(path)
		if ext == ".js" || ext == ".ts" || ext == ".mjs" || ext == ".cjs" {
			if err := e.scanFile(path); err != nil {
				e.log.Debug("error processing file", "file", path, "error", err)
			}
		}

		return nil
	})
}

func (e *RouteExtractor) GetRoutes() []RoutePattern {
	return e.routes
}

// CleanupRegexPath converts regex route patterns to simplified path patterns
// with dynamic segments replaced by :id placeholder.
// Example: "/^\\/api\\/v1\\/products\\/[a-zA-Z0-9-]+$/" -> "/api/v1/products/:id"
func (e *RouteExtractor) CleanupRegexPath(path string) string {
	// If it's not a regex pattern (doesn't start /), return blank
	if !strings.HasPrefix(path, "/") || len(path) < 2 {
		return ""
	}

	// Remove the leading and trailing / markers
	pattern := path

	// Replace the typical regex patterns found in http dispatcher
	pattern = e.patterns.RegexPattern.ReplaceAllString(pattern, "")

	// Replace multiple consecutive slashes with a single slash
	pattern = e.patterns.MultipleSlashPattern.ReplaceAllString(pattern, "/")

	// Remove trailing slash
	if len(pattern) > 1 && strings.HasSuffix(pattern, "/") {
		pattern = pattern[:len(pattern)-1]
	}

	parts := strings.Split(pattern, "/")
	keep := make([]string, 0, len(parts))

	for i, p := range parts {
		p := strings.Trim(p, " ")
		if p == "" {
			continue
		}
		switch p[0] {
		case ':':
			p = ":" + e.patterns.CleanID.ReplaceAllString(parts[i], "")
			keep = append(keep, p)
			continue
		case '{':
			if p[len(p)-1] == '}' {
				p = "{" + e.patterns.CleanID.ReplaceAllString(parts[i], "") + "}"
				keep = append(keep, p)
				continue
			}
		case '[':
			if p[len(p)-1] == ']' {
				p = "[" + e.patterns.CleanID.ReplaceAllString(parts[i], "") + "]"
				keep = append(keep, p)
				continue
			}

		}

		qPos := strings.Index(p, "?")
		if qPos >= 0 {
			p = p[:qPos]
		}

		if !e.patterns.ValidPathChars.MatchString(p) {
			p = ":id"
		}

		keep = append(keep, p)
	}

	pattern = strings.Join(keep, "/")

	// Ensure the path starts with /
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}

	return pattern
}

func (e *RouteExtractor) GetHarvestedRoutes() []string {
	dedup := map[string]struct{}{}

	for _, r := range e.routes {
		route := e.CleanupRegexPath(r.Path)
		if route != "" && route != "/" {
			dedup[route] = struct{}{}
		}
	}

	result := make([]string, 0, len(dedup))
	for k := range dedup {
		result = append(result, k)
	}

	return result
}

func (e *RouteExtractor) FirstArg(args []string) string {
	firstArg := ""
	for _, a := range args {
		if a == "" || a[0] == '-' || a == "inspect" {
			continue
		}
		firstArg = a
		break
	}

	return firstArg
}

// testing
var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

func ExtractNodejsRoutes(pid int32) (*RouteHarvesterResult, error) {
	rootDir := rootDirForPID(pid)
	_, args, err := cmdlineForPID(pid)
	if err != nil {
		return nil, fmt.Errorf("error finding cmd line, error %w", err)
	}
	workdir, err := cwdForPID(pid)
	if err != nil {
		return nil, fmt.Errorf("error finding cwd, error %w", err)
	}
	jsExtractor := NewRouteExtractor()

	firstArg := jsExtractor.FirstArg(args)

	dir := FindScriptDirectory(rootDir, firstArg, workdir)
	if dir == "" {
		return nil, fmt.Errorf("failed to find script directory for pid %d, script %s, cwd %s", pid, firstArg, workdir)
	}

	if err := jsExtractor.extractNextJSRoutesFromManifest(dir); err != nil {
		jsExtractor.log.Debug("error extracting next.js routes",
			"dir", dir,
			"error", err)
	}

	err = jsExtractor.ScanDirectory(dir)
	if err != nil {
		return nil, fmt.Errorf("error scanning directory, error %w", err)
	}

	routes := jsExtractor.GetHarvestedRoutes()

	r := RouteHarvesterResult{
		Routes: routes,
		Kind:   CompleteRoutes,
	}

	return &r, nil
}
