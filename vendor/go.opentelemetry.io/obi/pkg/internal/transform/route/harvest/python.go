// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
	"go.opentelemetry.io/obi/pkg/internal/pythontools"
)

const (
	maxPythonFileBytes = MaxJSFileScanBytes
	maxPythonFiles     = 10_000
	pyLit              = `(?:[rRuU])?(?:"([^"\r\n]*)"|'([^'\r\n]*)')`
	pyObj              = `(?:[A-Za-z_][A-Za-z0-9_]*\.)+`
)

var pySkipDirs = map[string]struct{}{
	".hg":           {},
	".nox":          {},
	".svn":          {},
	".tox":          {},
	".venv":         {},
	"__pycache__":   {},
	"env":           {},
	"site-packages": {},
	"venv":          {},
}

func ExtractPythonRoutes(fi *exec.FileInfo) (*RouteHarvesterResult, error) {
	if fi == nil {
		return nil, errors.New("python route harvesting requires process file info")
	}

	dir, err := pythontools.AppDirForPID(fi.Pid(), fi.ServiceAttrs().EnvVars)
	if err != nil {
		return nil, err
	}
	return extractPythonRoutes(dir)
}

func extractPythonRoutes(dir string) (*RouteHarvesterResult, error) {
	log := slog.With("component", "route.harvester.python")
	e := pythonExtractor{
		routes:       map[string]struct{}{},
		djangoRoutes: map[string][]djangoRoute{},
	}
	kind := PartialRoutes
	err := walkPythonFiles(dir, func(path string) {
		if err := e.scanFile(path); err != nil {
			log.Debug("error processing file", "file", path, "error", err)
			return
		}
		if len(e.djangoRoutes[path]) > 0 {
			kind = CompleteRoutes
		}
	})
	if err != nil {
		return nil, fmt.Errorf("scan Python directory: %w", err)
	}

	resolveDjangoRoutes(dir, e.djangoRoutes, e.routes)

	result := make([]string, 0, len(e.routes))
	for route := range e.routes {
		result = append(result, route)
	}
	sort.Strings(result)
	return &RouteHarvesterResult{Routes: result, Kind: kind}, nil
}

func walkPythonFiles(root string, fn func(string)) error {
	return walkPythonFilesN(root, maxPythonFiles, fn)
}

func walkPythonFilesN(root string, maxFiles int, fn func(string)) error {
	files, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	scanned := 0
	limit := false
	for _, file := range files {
		path := filepath.Join(root, file.Name())
		if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if skipPythonDir(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() || info.Size() > maxPythonFileBytes || filepath.Ext(path) != ".py" {
				return nil
			}
			scanned++
			fn(path)
			if scanned >= maxFiles {
				limit = true
				return filepath.SkipAll
			}
			return nil
		}); err != nil {
			return err
		}
		if limit {
			break
		}
	}
	return nil
}

func skipPythonDir(name string) bool {
	if _, ok := skipDirs[name]; ok {
		return true
	}
	_, ok := pySkipDirs[name]
	return ok
}

type pythonExtractor struct {
	routes       map[string]struct{}
	djangoRoutes map[string][]djangoRoute
}

func (e *pythonExtractor) scanFile(path string) error {
	file, _ := langtools.OpenMetadataFile(path, maxPythonFileBytes)
	if file == nil {
		return nil
	}
	defer file.Close()

	var djangoRoutes []djangoRoute
	djangoAliases := map[string]string{}
	hasDjangoPath := false
	scanStmt := func(text string) {
		scanPythonStmt(text, e.routes)
		if match := djangoFromImportAliasPattern.FindStringSubmatch(text); match != nil {
			djangoAliases[match[3]] = match[1] + "." + match[2]
		} else if match := djangoImportAliasPattern.FindStringSubmatch(text); match != nil {
			djangoAliases[match[2]] = match[1]
		}
		// Remember the Django path import so subsequent statements can be scanned as Django routes.
		if djangoPathImportPattern.MatchString(text) {
			hasDjangoPath = true
		}
		if hasDjangoPath {
			djangoRoutes = append(djangoRoutes, scanDjango(text, djangoAliases)...)
		}
	}

	scan := bufio.NewScanner(file)
	var stmt strings.Builder
	depth := 0
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if stmt.Len() == 0 {
			depth = parenDelta(line)
			startsStmt := startsFastAPI(line) || startsFlask(line) ||
				djangoImportStart.MatchString(line) ||
				hasDjangoPath && (djangoPathStart.MatchString(line) || djangoI18nStart.MatchString(line))
			if !startsStmt || depth <= 0 {
				scanStmt(line)
				continue
			}
			stmt.WriteString(line)
			continue
		}

		stmt.WriteByte(' ')
		stmt.WriteString(line)
		depth += parenDelta(line)
		if depth <= 0 {
			scanStmt(stmt.String())
			stmt.Reset()
			depth = 0
		}
	}
	if err := scan.Err(); err != nil {
		return err
	}
	e.djangoRoutes[path] = djangoRoutes
	return nil
}

func scanPythonStmt(stmt string, routes map[string]struct{}) {
	scanFastAPI(stmt, routes)
	scanFlask(stmt, routes)
}

func parenDelta(line string) int {
	return strings.Count(line, "(") - strings.Count(line, ")")
}

func addPyMatch(routes map[string]struct{}, re *regexp.Regexp, line string) {
	match := re.FindStringSubmatch(line)
	for i := 1; i < len(match); i++ {
		if strings.HasPrefix(match[i], "/") {
			routes[match[i]] = struct{}{}
			return
		}
	}
}
