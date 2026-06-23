// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package java extracts Java HTTP route declarations from application class files.
package java // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/java"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

const (
	MaxJavaArchiveScanBytes int64 = 256 * 1024 * 1024
	MaxJavaClassScanBytes   int64 = 2 * 1024 * 1024
	MaxJavaClassesScanned         = 50_000
	MaxJavaRoutes                 = 10_000
)

type Extractor struct {
	log *slog.Logger

	classesScanned int
	routes         map[string]struct{}

	classLimitLogged bool
	routeLimitLogged bool
}

func ExtractRoutes(ctx context.Context, fileInfo *exec.FileInfo) ([]string, error) {
	return NewExtractor().ExtractRoutes(ctx, fileInfo)
}

func NewExtractor() *Extractor {
	return &Extractor{
		log:    slog.With("component", "route.harvester.java"),
		routes: map[string]struct{}{},
	}
}

func (e *Extractor) ExtractRoutes(ctx context.Context, fileInfo *exec.FileInfo) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fileInfo == nil {
		return nil, errors.New("java route harvesting requires process file info")
	}

	roots, err := e.findScanRoots(fileInfo)
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no Java application scan roots found for pid %d", fileInfo.Pid())
	}

	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e.routeLimitReached() || e.classLimitReached() {
			break
		}
		if root.dir {
			if err := e.scanDir(ctx, root.path); err != nil {
				return nil, err
			}
			continue
		}
		if err := e.scanArchive(ctx, root.path); err != nil {
			return nil, err
		}
	}

	return sortRoutes(mapKeys(e.routes)), nil
}

func (e *Extractor) addRoutes(routes []string) {
	for _, route := range routes {
		if e.routeLimitReached() {
			return
		}

		route, ok := normalizeRoute(route)
		if !ok {
			continue
		}
		e.routes[route] = struct{}{}
	}
}

func (e *Extractor) routeLimitReached() bool {
	if len(e.routes) < MaxJavaRoutes {
		return false
	}
	if !e.routeLimitLogged {
		e.log.Info("java route harvest route limit reached", "limit", MaxJavaRoutes)
		e.routeLimitLogged = true
	}
	return true
}

func (e *Extractor) classLimitReached() bool {
	if e.classesScanned < MaxJavaClassesScanned {
		return false
	}
	if !e.classLimitLogged {
		e.log.Info("java route harvest class scan limit reached", "limit", MaxJavaClassesScanned)
		e.classLimitLogged = true
	}
	return true
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortRoutes(routes []string) []string {
	sort.Slice(routes, func(i, j int) bool {
		hasWildcardI := routeHasWildcardSegment(routes[i])
		hasWildcardJ := routeHasWildcardSegment(routes[j])

		if hasWildcardI && !hasWildcardJ {
			return false
		}
		if !hasWildcardI && hasWildcardJ {
			return true
		}

		return len(routes[i]) > len(routes[j])
	})

	return routes
}

func routeHasWildcardSegment(route string) bool {
	for _, segment := range strings.Split(route, "/") {
		if segment == "" {
			continue
		}
		if segment == "*" || routeSegmentIsParameter(segment) {
			return true
		}
	}
	return false
}

func routeSegmentIsParameter(segment string) bool {
	if strings.HasPrefix(segment, ":") {
		return routeParameterName(segment[1:])
	}
	if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
		return routeParameterName(strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}"))
	}
	return false
}

func routeParameterName(name string) bool {
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}
