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
	routes := map[string]struct{}{}
	err := walkPythonFiles(dir, func(path string) error {
		if err := scanPythonFile(path, routes); err != nil {
			log.Debug("error processing file", "file", path, "error", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan Python directory: %w", err)
	}

	result := make([]string, 0, len(routes))
	for route := range routes {
		result = append(result, route)
	}
	sort.Strings(result)
	return &RouteHarvesterResult{Routes: result, Kind: PartialRoutes}, nil
}

func walkPythonFiles(root string, fn func(string) error) error {
	return walkPythonFilesN(root, maxPythonFiles, fn)
}

func walkPythonFilesN(root string, maxFiles int, fn func(string) error) error {
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
			if err := fn(path); err != nil {
				return err
			}
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

func scanPythonFile(path string, routes map[string]struct{}) error {
	file, _ := langtools.OpenMetadataFile(path, maxPythonFileBytes)
	if file == nil {
		return nil
	}
	defer file.Close()

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
			if (!startsFastAPI(line) && !startsFlask(line)) || depth <= 0 {
				scanPythonStmt(line, routes)
				continue
			}
			stmt.WriteString(line)
			continue
		}

		stmt.WriteByte(' ')
		stmt.WriteString(line)
		depth += parenDelta(line)
		if depth <= 0 {
			scanPythonStmt(stmt.String(), routes)
			stmt.Reset()
			depth = 0
		}
	}
	return scan.Err()
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
