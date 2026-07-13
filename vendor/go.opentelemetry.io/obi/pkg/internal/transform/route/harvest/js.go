// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

// MaxJSFileScanBytes caps opportunistic JS/TS source scans to avoid spending
// unbounded work on large application files.
const MaxJSFileScanBytes int64 = 10 * 1024 * 1024

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

	// Nest marks routes declared through NestJS decorators; the app-level
	// global prefix and URI version apply to them at harvest time.
	Nest bool
	// Version is the NestJS URI version of the route ('2' in /v2/...): from
	// @Version() on the method, or the version of its @Controller().
	Version string
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
	// NestJS controller decorator: @Controller('prefix'), @Controller()
	NestJSController *regexp.Regexp
	// NestJS controller decorator, object form: @Controller({ path: 'x', version: '1' })
	NestJSControllerObject *regexp.Regexp
	// NestJS controller decorator, array form: @Controller(['x', 'y'])
	NestJSControllerArray *regexp.Regexp
	// NestJS version decorator: @Version('1'), @Version(['1', '2'])
	NestJSVersion *regexp.Regexp
	// NestJS controller decorator with any argument shape, used as a fail-safe
	// reset when the argument is not statically resolvable
	NestJSControllerAny *regexp.Regexp
	// NestJS decorators in compiled output: (0, common_1.Get)('store')
	CompiledNestMethod *regexp.Regexp
	// NestJS controller decorator in compiled output: (0, common_1.Controller)('invoice')
	CompiledNestController *regexp.Regexp
	// Compiled controller decorator, object/array forms
	CompiledNestControllerObject *regexp.Regexp
	CompiledNestControllerArray  *regexp.Regexp
	// Compiled version decorator: (0, common_1.Version)('2')
	CompiledNestVersion *regexp.Regexp
	// NestJS global prefix: app.setGlobalPrefix('api')
	SetGlobalPrefix *regexp.Regexp
	// defaultVersion option of app.enableVersioning()
	DefaultVersion *regexp.Regexp

	// 'path'/'version' values inside a @Controller() object argument; the value
	// may be a single quoted string or an array of them
	ObjectPathValue    *regexp.Regexp
	ObjectVersionValue *regexp.Regexp
	// a single quoted string; applied with FindAll to collect list values
	QuotedString *regexp.Regexp
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

		// Matches: @Get('/users/:id'), @Post('/items'), and bare decorators such
		// as @Post(), which NestJS routes at the controller prefix
		NestJS: regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|Options|Head|All)\s*\(\s*(?:['"\x60]([^'"\x60]*?)['"\x60]\s*)?\)`),

		// Matches: @Controller('users'), @Controller("api/v1/posts"), @Controller()
		NestJSController: regexp.MustCompile(`@Controller\s*\(\s*(?:['"\x60]([^'"\x60]*)['"\x60])?\s*\)`),

		// Matches: @Controller({ path: 'catalog', version: '2' })
		NestJSControllerObject: regexp.MustCompile(`@Controller\s*\(\s*\{([^}]*)\}`),

		// Matches: @Controller(['ledger', 'books'])
		NestJSControllerArray: regexp.MustCompile(`@Controller\s*\(\s*\[([^\]]*)\]`),

		// Matches: @Version('3'), @Version(['1', '2']), @Version(VERSION_NEUTRAL)
		NestJSVersion: regexp.MustCompile(`@Version\s*\(([^)]*)\)`),

		// Matches any remaining @Controller(...) shape, e.g. @Controller(SOME_CONST)
		NestJSControllerAny: regexp.MustCompile(`@Controller\s*\(`),

		// TypeScript compilers lower decorators to helper calls referencing the
		// decorator factory through the imported module object:
		//   (0, common_1.Get)('store')   tsc
		//   (0, _common.Get)(':id')      swc
		//   common_1.Get('store')        direct emit
		// The class association ("which @Controller() prefixes this @Get()?") is
		// scattered across __decorate() blocks, so compiled matches are harvested
		// as route fragments and matched partially instead of joined.
		CompiledNestMethod:           regexp.MustCompile(`[\w$]+\.(Get|Post|Put|Patch|Delete|Options|Head|All)\)?\s*\(\s*(?:['"\x60]([^'"\x60]*)['"\x60]\s*)?\)`),
		CompiledNestController:       regexp.MustCompile(`[\w$]+\.Controller\)?\s*\(\s*(?:['"\x60]([^'"\x60]*)['"\x60]\s*)?\)`),
		CompiledNestControllerObject: regexp.MustCompile(`[\w$]+\.Controller\)?\s*\(\s*\{([^}]*)\}`),
		CompiledNestControllerArray:  regexp.MustCompile(`[\w$]+\.Controller\)?\s*\(\s*\[([^\]]*)\]`),
		CompiledNestVersion:          regexp.MustCompile(`[\w$]+\.Version\)?\s*\(([^)]*)\)`),

		// Matches: app.setGlobalPrefix('api')
		SetGlobalPrefix: regexp.MustCompile(`\.setGlobalPrefix\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]`),

		// Matches: defaultVersion: '1' inside app.enableVersioning({...})
		DefaultVersion: regexp.MustCompile(`defaultVersion\s*:\s*['"\x60]([^'"\x60]+)['"\x60]`),

		ObjectPathValue:    regexp.MustCompile(`path\s*:\s*(\[[^\]]*\]|['"\x60][^'"\x60]*['"\x60])`),
		ObjectVersionValue: regexp.MustCompile(`version\s*:\s*(\[[^\]]*\]|['"\x60][^'"\x60]*['"\x60])`),
		QuotedString:       regexp.MustCompile(`['"\x60]([^'"\x60]*)['"\x60]`),

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

	// nestPrefixes holds the path prefix(es) of the NestJS @Controller()
	// decorator most recently seen in the file being scanned (plural for the
	// array form, @Controller(['a', 'b'])). TypeScript decorators always live
	// in the same file as the class they decorate, with @Controller() preceding
	// the method decorators, so tracking the last seen prefixes per file is
	// enough to resolve the full route of each method decorator.
	nestPrefixes []string
	// nestCtrlVersions holds the version(s) declared by the current
	// @Controller({ version: ... }), applying to its methods unless overridden
	nestCtrlVersions []string
	// pendingNestVersions holds the version(s) of a @Version() decorator seen
	// in the decorator stack of the currently buffered method
	pendingNestVersions []string
	// pendingNestMethod buffers the method decorator of the decorator stack
	// currently being scanned. Decorator order within a stack is arbitrary
	// (@Version() may appear above or below @Get()), so the route is emitted
	// only when the stack ends: at the first non-decorator line, the next
	// method or controller decorator, or the end of the file.
	pendingNestMethod *RoutePattern
	// inEnableVersioning tracks a multi-line app.enableVersioning({...}) call
	// until its closing parenthesis
	inEnableVersioning bool
	// enableVersioningTypeSeen tracks whether the current enableVersioning call
	// named an explicit VersioningType (URI is NestJS's default when it didn't)
	enableVersioningTypeSeen bool

	// application-level NestJS settings, harvested from any scanned file
	// (typically main.ts) and applied to Nest routes after the scan
	globalPrefix   string
	uriVersioning  bool
	defaultVersion string

	// compiled switches the scan to compiled-output mode: decorators lowered by
	// tsc/swc are recognized and harvested as route fragments (prefix/path
	// association is lost in compiled code), and the fallback pattern is
	// disabled because compiled code is full of path-like string literals.
	compiled bool
}

// nestVersionNeutral marks routes explicitly declared version-neutral
// (@Version(VERSION_NEUTRAL)): no version segment, even with a default version.
const nestVersionNeutral = "\x00neutral"

func NewRouteExtractor() *RouteExtractor {
	return &RouteExtractor{
		patterns: newFrameworkPatterns(),
		routes:   []RoutePattern{},
		log:      slog.With("component", "route.harvester.js"),
	}
}

// NewCompiledRouteExtractor returns an extractor for compiled/transpiled output
// (e.g. a NestJS app shipping only dist/). Its routes are fragments meant for
// partial matching.
func NewCompiledRouteExtractor() *RouteExtractor {
	e := NewRouteExtractor()
	e.compiled = true
	return e
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

// quotedStrings returns the contents of every quoted string in s: the single
// value of 'x' as well as every element of ['x', 'y'].
func (e *RouteExtractor) quotedStrings(s string) []string {
	matches := e.patterns.QuotedString.FindAllStringSubmatch(s, -1)
	result := make([]string, 0, len(matches))
	for _, m := range matches {
		result = append(result, m[1])
	}
	return result
}

// setNestController tracks the prefixes and versions of the current NestJS
// @Controller() decorator, which apply to every method decorator that follows
// it in the same file. A method still buffered for the previous controller is
// flushed first, against that controller's prefixes.
func (e *RouteExtractor) setNestController(prefixes, versions []string) {
	e.flushNestMethod()
	if len(prefixes) == 0 {
		prefixes = []string{""}
	}
	e.nestPrefixes = prefixes
	e.nestCtrlVersions = versions
	e.pendingNestVersions = nil
}

// flushNestMethod emits the buffered method decorator, resolving its versions
// (from @Version() anywhere in its decorator stack, the controller's version,
// or none) and joining its path with every controller prefix.
func (e *RouteExtractor) flushNestMethod() {
	m := e.pendingNestMethod
	if m == nil {
		return
	}
	e.pendingNestMethod = nil

	versions := e.pendingNestVersions
	e.pendingNestVersions = nil
	if len(versions) == 0 {
		versions = e.nestCtrlVersions
	}
	if len(versions) == 0 {
		versions = []string{""}
	}
	prefixes := e.nestPrefixes
	if len(prefixes) == 0 {
		prefixes = []string{""}
	}

	for _, prefix := range prefixes {
		for _, version := range versions {
			e.routes = append(e.routes, RoutePattern{
				Method:  m.Method,
				Path:    joinNestPaths(prefix, m.Path),
				File:    m.File,
				Line:    m.Line,
				Nest:    true,
				Version: version,
			})
		}
	}
}

func (e *RouteExtractor) handleNestJSController(line string) bool {
	// object form: @Controller({ path: 'x' | ['x', 'y'], version: '1' | ['1', '2'] })
	if matches := e.patterns.NestJSControllerObject.FindStringSubmatch(line); matches != nil {
		var prefixes, versions []string
		if pm := e.patterns.ObjectPathValue.FindStringSubmatch(matches[1]); pm != nil {
			prefixes = e.quotedStrings(pm[1])
		}
		if vm := e.patterns.ObjectVersionValue.FindStringSubmatch(matches[1]); vm != nil {
			versions = e.quotedStrings(vm[1])
		}
		e.setNestController(prefixes, versions)
		return true
	}
	// array form: @Controller(['ledger', 'books'])
	if matches := e.patterns.NestJSControllerArray.FindStringSubmatch(line); matches != nil {
		e.setNestController(e.quotedStrings(matches[1]), nil)
		return true
	}
	// string form: @Controller('invoice'), @Controller()
	if matches := e.patterns.NestJSController.FindStringSubmatch(line); matches != nil {
		e.setNestController([]string{matches[1]}, nil)
		return true
	}
	// non-literal argument (@Controller(SOME_CONST)): the prefix cannot be
	// resolved statically; reset the state so the previous controller's prefix
	// does not leak into this controller's methods
	if e.patterns.NestJSControllerAny.MatchString(line) {
		e.setNestController(nil, nil)
		return true
	}
	return false
}

// handleNestJSVersion tracks a @Version() decorator; it applies to the next
// method decorator in the file. Non-string arguments (VERSION_NEUTRAL) declare
// the route version-neutral.
func (e *RouteExtractor) handleNestJSVersion(line string) bool {
	matches := e.patterns.NestJSVersion.FindStringSubmatch(line)
	if matches == nil {
		return false
	}
	versions := e.quotedStrings(matches[1])
	if len(versions) == 0 {
		versions = []string{nestVersionNeutral}
	}
	e.pendingNestVersions = versions
	return true
}

// handleSetGlobalPrefix harvests app.setGlobalPrefix('api'). In source mode the
// prefix is applied to every Nest route after the scan; in compiled mode routes
// are fragments, so the prefix becomes a fragment of its own.
func (e *RouteExtractor) handleSetGlobalPrefix(filePath, line string, lineNum int) bool {
	matches := e.patterns.SetGlobalPrefix.FindStringSubmatch(line)
	if matches == nil {
		return false
	}
	if e.compiled {
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   ensureLeadingSlash(matches[1]),
			File:   filePath,
			Line:   lineNum,
		})
	} else {
		e.globalPrefix = matches[1]
	}
	return true
}

// handleEnableVersioning detects app.enableVersioning(...), tracking the call
// across lines until its closing parenthesis. URI versioning is NestJS's
// default type, so a call that names no VersioningType enables it. In compiled
// mode the defaultVersion becomes a /v<version> route fragment (fragments are
// not Nest-marked, so the source-mode version prefixing does not reach them).
func (e *RouteExtractor) handleEnableVersioning(filePath, line string, lineNum int) bool {
	entered := strings.Contains(line, ".enableVersioning")
	if !entered && !e.inEnableVersioning {
		return false
	}
	if entered {
		e.inEnableVersioning = true
		e.enableVersioningTypeSeen = false
	}
	if strings.Contains(line, "VersioningType.") {
		e.enableVersioningTypeSeen = true
		if strings.Contains(line, "VersioningType.URI") {
			e.uriVersioning = true
		}
	}
	if matches := e.patterns.DefaultVersion.FindStringSubmatch(line); matches != nil {
		e.defaultVersion = matches[1]
		if e.compiled {
			e.routes = append(e.routes, RoutePattern{
				Method: "ALL",
				Path:   "/v" + matches[1],
				File:   filePath,
				Line:   lineNum,
			})
		}
	}
	if strings.Contains(line, ")") {
		e.inEnableVersioning = false
		if !e.enableVersioningTypeSeen {
			e.uriVersioning = true
		}
	}
	return true
}

// joinNestPaths combines a NestJS controller prefix with a method decorator
// path into a single absolute route, normalizing slashes. NestJS treats both
// parts as relative regardless of leading/trailing slashes.
func joinNestPaths(prefix, path string) string {
	prefix = strings.Trim(prefix, "/")
	path = strings.Trim(path, "/")
	switch {
	case prefix == "":
		return "/" + path
	case path == "":
		return "/" + prefix
	default:
		return "/" + prefix + "/" + path
	}
}

func (e *RouteExtractor) handleNestJS(filePath, line string, lineNum int) bool {
	matches := e.patterns.NestJS.FindStringSubmatch(line)
	if len(matches) <= 2 {
		return false
	}

	// a previously buffered method's decorator stack ends here
	e.flushNestMethod()
	e.pendingNestMethod = &RoutePattern{
		Method: strings.ToUpper(matches[1]),
		Path:   matches[2],
		File:   filePath,
		Line:   lineNum,
	}
	return true
}

// handleCompiledNestController harvests the prefix(es) of a compiled
// @Controller() decorator as standalone route fragments. For the object form,
// declared versions become fragments too (/v2).
func (e *RouteExtractor) handleCompiledNestController(filePath, line string, lineNum int) bool {
	addFragment := func(path string) {
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   ensureLeadingSlash(path),
			File:   filePath,
			Line:   lineNum,
		})
	}
	if matches := e.patterns.CompiledNestControllerObject.FindStringSubmatch(line); matches != nil {
		if pm := e.patterns.ObjectPathValue.FindStringSubmatch(matches[1]); pm != nil {
			for _, prefix := range e.quotedStrings(pm[1]) {
				addFragment(prefix)
			}
		}
		if vm := e.patterns.ObjectVersionValue.FindStringSubmatch(matches[1]); vm != nil {
			for _, version := range e.quotedStrings(vm[1]) {
				addFragment("v" + version)
			}
		}
		return true
	}
	if matches := e.patterns.CompiledNestControllerArray.FindStringSubmatch(line); matches != nil {
		for _, prefix := range e.quotedStrings(matches[1]) {
			addFragment(prefix)
		}
		return true
	}
	matches := e.patterns.CompiledNestController.FindStringSubmatch(line)
	if matches == nil {
		return false
	}
	if matches[1] != "" {
		addFragment(matches[1])
	}
	return true
}

// handleCompiledNestVersion harvests a compiled @Version() decorator as /vN
// route fragments.
func (e *RouteExtractor) handleCompiledNestVersion(filePath, line string, lineNum int) bool {
	matches := e.patterns.CompiledNestVersion.FindStringSubmatch(line)
	if matches == nil {
		return false
	}
	for _, version := range e.quotedStrings(matches[1]) {
		e.routes = append(e.routes, RoutePattern{
			Method: "ALL",
			Path:   "/v" + version,
			File:   filePath,
			Line:   lineNum,
		})
	}
	return true
}

// handleCompiledNestMethod harvests the path of a compiled method decorator
// ((0, common_1.Get)(':id')) as a standalone route fragment. Bare decorators
// carry no path: the request is routed at the controller prefix, which is
// already harvested as its own fragment.
func (e *RouteExtractor) handleCompiledNestMethod(filePath, line string, lineNum int) bool {
	matches := e.patterns.CompiledNestMethod.FindStringSubmatch(line)
	if matches == nil {
		return false
	}
	if matches[2] != "" {
		e.routes = append(e.routes, RoutePattern{
			Method: strings.ToUpper(matches[1]),
			Path:   ensureLeadingSlash(matches[2]),
			File:   filePath,
			Line:   lineNum,
		})
	}
	return true
}

func ensureLeadingSlash(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

// sortRouteFragments orders route fragments for the PartialRouteMatcher, which
// tries fragments in definition order: fewer parameter segments first (literal
// fragments must win over catch-alls), longer fragments next (more specific),
// then lexicographic for determinism.
func sortRouteFragments(fragments []string) {
	segments := func(f string) []string { return strings.Split(strings.Trim(f, "/"), "/") }
	params := func(f string) int {
		n := 0
		for _, s := range segments(f) {
			if strings.HasPrefix(s, ":") || (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) {
				n++
			}
		}
		return n
	}
	sort.Slice(fragments, func(i, j int) bool {
		pi, pj := params(fragments[i]), params(fragments[j])
		if pi != pj {
			return pi < pj
		}
		si, sj := len(segments(fragments[i])), len(segments(fragments[j]))
		if si != sj {
			return si > sj
		}
		return fragments[i] < fragments[j]
	})
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
			Method:  "ALL",
			Path:    matches[0],
			File:    filePath,
			Line:    lineNum,
			Handler: fallbackHandler,
		})
		return true
	}

	return false
}

// fallbackHandler marks routes guessed from arbitrary path-like string
// literals, as opposed to routes declared through a recognized framework API.
const fallbackHandler = "fallback"

// FrameworkRoutes returns the number of harvested routes that were declared
// through a recognized framework API (i.e. everything but fallback guesses).
func (e *RouteExtractor) FrameworkRoutes() int {
	n := 0
	for i := range e.routes {
		if e.routes[i].Handler != fallbackHandler {
			n++
		}
	}
	return n
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

// ScanJSFileLines opens a JS/TS file and calls fn for each non-empty,
// non-comment line (trimmed). It skips non-regular files and files larger than
// MaxJSFileScanBytes. The callback receives the trimmed line and returns true
// to stop scanning early, or false to continue.
func ScanJSFileLines(path string, fn func(line string) bool) error {
	file, ok, err := openJSFileForScan(path)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer file.Close()

	inBlockComment := false
	scanner := bufio.NewScanner(io.LimitReader(file, MaxJSFileScanBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if inBlockComment {
			if strings.Contains(line, "*/") {
				inBlockComment = false
			}
			continue
		}

		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if strings.HasPrefix(line, "/*") {
			if !strings.Contains(line, "*/") {
				inBlockComment = true
			}
			continue
		}

		if fn(line) {
			return nil
		}
	}

	return scanner.Err()
}

func (e *RouteExtractor) scanFile(filePath string) error {
	file, ok, err := openJSFileForScan(filePath)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(io.LimitReader(file, MaxJSFileScanBytes))
	lineNum := 0
	var line string
	var save string

	// NestJS controller prefixes, versions, and buffered decorator stacks
	// never span files
	e.nestPrefixes = nil
	e.nestCtrlVersions = nil
	e.pendingNestVersions = nil
	e.pendingNestMethod = nil
	e.inEnableVersioning = false

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

		// a non-decorator line (typically the method signature) ends the
		// decorator stack of a buffered NestJS method
		if e.pendingNestMethod != nil && !strings.HasPrefix(trimmed, "@") {
			e.flushNestMethod()
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

		// NestJS application-level settings (typically in main.ts)
		if e.handleSetGlobalPrefix(filePath, line, lineNum) {
			continue
		}
		if e.handleEnableVersioning(filePath, line, lineNum) {
			continue
		}

		if e.compiled {
			// Note: the generic patterns above still run in compiled mode; they
			// match compiled Express-style calls but also unrelated ones like
			// configService.get('X'). The path cleanup's leading-slash
			// requirement filters out nearly all of that, and surviving literal
			// fragments are benign for partial matching.

			// NestJS decorators as lowered by tsc/swc, harvested as fragments
			if e.handleCompiledNestController(filePath, line, lineNum) {
				continue
			}
			if e.handleCompiledNestVersion(filePath, line, lineNum) {
				continue
			}
			if e.handleCompiledNestMethod(filePath, line, lineNum) {
				continue
			}
		} else {
			// NestJS @Controller() prefix, applied to the method decorators below it
			if e.handleNestJSController(line) {
				continue
			}

			// NestJS @Version(), applied to the next method decorator
			if e.handleNestJSVersion(line) {
				continue
			}

			// NestJS decorators
			if e.handleNestJS(filePath, line, lineNum) {
				continue
			}
		}

		// HttpDispatcher
		if e.handleHTTPDispatcher(filePath, line, lineNum) {
			continue
		}

		// Fallback when none matches. Compiled code is full of path-like string
		// literals, so no fallback guesses are harvested from it.
		if !e.compiled && e.handleFallback(filePath, line, lineNum) {
			continue
		}

		save = line
	}

	// the file may end while a method decorator stack is still buffered
	e.flushNestMethod()

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (e *RouteExtractor) ScanDirectory(root string) error {
	walk := WalkJSFiles
	if e.compiled {
		walk = WalkCompiledJSFiles
	}
	return walk(root, func(path string) error {
		if err := e.scanFile(path); err != nil {
			e.log.Debug("error processing file", "file", path, "error", err)
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
		var route string
		if r.Path == "/" {
			// the root route survives cleanup so that the version and global
			// prefix can still apply (a bare @Get() under setGlobalPrefix('api')
			// serves /api); a plain "/" is filtered below as before
			route = "/"
		} else {
			route = e.CleanupRegexPath(r.Path)
		}
		if route == "" {
			continue
		}
		if r.Nest {
			// URI-versioned apps serve Nest routes under /v<version>/
			if e.uriVersioning && r.Version != nestVersionNeutral {
				version := r.Version
				if version == "" {
					version = e.defaultVersion
				}
				if version != "" {
					route = joinNestPaths("v"+version, route)
				}
			}
			// the app-level global prefix goes in front of everything
			if e.globalPrefix != "" {
				route = joinNestPaths(e.globalPrefix, route)
			}
		}
		if route != "/" {
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
	return FirstArg(args)
}

// FirstArg returns the first non-flag argument from a Node.js command line,
// skipping flags (starting with '-') and the "inspect" keyword.
func FirstArg(args []string) string {
	for _, a := range args {
		if a == "" || a[0] == '-' || a == "inspect" {
			continue
		}
		return a
	}
	return ""
}

// testing
var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

// FindNodeJSAppDir locates the root directory of a Node.js application by
// reading its command line and working directory from /proc.
func FindNodeJSAppDir(pid app.PID) (string, error) {
	rootDir := rootDirForPID(pid)
	_, args, err := cmdlineForPID(pid)
	if err != nil {
		return "", fmt.Errorf("error finding cmd line: %w", err)
	}
	workdir, err := cwdForPID(pid)
	if err != nil {
		return "", fmt.Errorf("error finding cwd: %w", err)
	}

	firstArg := FirstArg(args)

	dir := FindScriptDirectory(rootDir, firstArg, workdir)
	if dir == "" {
		return "", fmt.Errorf("failed to find script directory for pid %d, script %s, cwd %s", pid, firstArg, workdir)
	}
	return dir, nil
}

// compiledSkipDirs is the skip list of the compiled-output scan: compiled
// JavaScript lives precisely in the directories the source scan skips.
var compiledSkipDirs = func() map[string]string {
	m := make(map[string]string, len(skipDirs))
	for k, v := range skipDirs {
		m[k] = v
	}
	delete(m, "dist")
	delete(m, "build")
	return m
}()

// WalkJSFiles walks a directory tree, skipping known non-application directories
// (node_modules, .git, system dirs, etc.), and calls fn for each regular JS/TS
// source file found (.js, .ts, .mjs, .cjs) that is not larger than
// MaxJSFileScanBytes. The callback can return filepath.SkipAll to stop the walk
// early.
func WalkJSFiles(root string, fn func(path string) error) error {
	return filepath.Walk(root, newJSFileWalker(root, skipDirs, false, fn))
}

// WalkCompiledJSFiles is WalkJSFiles for compiled output: it descends into
// compiled-output directories (dist, build) — including when root itself is
// one, as happens when the process entrypoint is an absolute path like
// /app/dist/main.js — so apps shipping only compiled code can be scanned.
func WalkCompiledJSFiles(root string, fn func(path string) error) error {
	return filepath.Walk(root, newJSFileWalker(root, compiledSkipDirs, true, fn))
}

func newJSFileWalker(root string, skip map[string]string, scanRoot bool, fn func(path string) error) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if scanRoot && path == root {
				return nil
			}
			name := info.Name()
			if name == "root" && path != root {
				return filepath.SkipDir
			}
			if _, ok := skip[name]; ok {
				return filepath.SkipDir
			}
			return nil
		}

		if !info.Mode().IsRegular() || info.Size() > MaxJSFileScanBytes {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".js" || ext == ".ts" || ext == ".mjs" || ext == ".cjs" {
			return fn(path)
		}

		return nil
	}
}

func ExtractNodejsRoutes(pid app.PID) (*RouteHarvesterResult, error) {
	dir, err := FindNodeJSAppDir(pid)
	if err != nil {
		return nil, err
	}

	jsExtractor := NewRouteExtractor()

	if err := jsExtractor.extractNextJSRoutesFromManifest(dir); err != nil {
		jsExtractor.log.Debug("error extracting next.js routes",
			"dir", dir,
			"error", err)
	}

	err = jsExtractor.ScanDirectory(dir)
	if err != nil {
		return nil, fmt.Errorf("error scanning directory, error %w", err)
	}

	// Routes declared through a recognized framework API are complete: prefix
	// and path are joined at harvest time and can be matched exactly.
	if jsExtractor.FrameworkRoutes() > 0 {
		return &RouteHarvesterResult{
			Routes: jsExtractor.GetHarvestedRoutes(),
			Kind:   CompleteRoutes,
		}, nil
	}

	// No framework routes in the sources: the app may ship only compiled
	// output (dist/, build/), which the source scan skips. Compiled decorators
	// lose the controller/method association, so their paths are harvested as
	// fragments and matched partially.
	compiledExtractor := NewCompiledRouteExtractor()
	if err := compiledExtractor.ScanDirectory(dir); err != nil {
		compiledExtractor.log.Debug("error scanning compiled output", "dir", dir, "error", err)
	}
	if fragments := compiledExtractor.GetHarvestedRoutes(); len(fragments) > 0 {
		sortRouteFragments(fragments)
		return &RouteHarvesterResult{
			Routes: fragments,
			Kind:   PartialRoutes,
		}, nil
	}

	// Neither sources nor compiled output declared routes: keep whatever the
	// fallback pattern guessed from the sources.
	return &RouteHarvesterResult{
		Routes: jsExtractor.GetHarvestedRoutes(),
		Kind:   CompleteRoutes,
	}, nil
}
