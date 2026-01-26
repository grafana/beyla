// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
)

type RouteHarvester struct {
	log      *slog.Logger
	java     *JavaRoutes
	disabled map[svc.InstrumentableType]struct{}
	cfg      *services.RouteHarvestingConfig
	timeout  time.Duration
	mux      *sync.Mutex

	// testing related
	javaExtractRoutes func(pid int32) (*RouteHarvesterResult, error)
	nodeExtractRoutes func(pid int32) (*RouteHarvesterResult, error)
}

type RouteHarvesterResultKind uint8

const (
	CompleteRoutes RouteHarvesterResultKind = iota + 1
	PartialRoutes
)

type RouteHarvesterResult struct {
	Routes []string
	Kind   RouteHarvesterResultKind
}

// HarvestError represents an error that occurred during route harvesting
type HarvestError struct {
	Message string
}

func (e *HarvestError) Error() string {
	return e.Message
}

func NewRouteHarvester(cfg *services.RouteHarvestingConfig, disabled []string, timeout time.Duration) *RouteHarvester {
	dMap := map[svc.InstrumentableType]struct{}{}
	for _, lang := range disabled {
		if strings.ToLower(lang) == svc.InstrumentableJava.String() {
			dMap[svc.InstrumentableJava] = struct{}{}
		}
		if strings.ToLower(lang) == svc.InstrumentableNodejs.String() {
			dMap[svc.InstrumentableNodejs] = struct{}{}
		}
	}

	h := &RouteHarvester{
		log:      slog.With("component", "route.harvester"),
		java:     NewJavaRoutesHarvester(),
		disabled: dMap,
		timeout:  timeout,
		cfg:      cfg,
		mux:      &sync.Mutex{},
	}

	h.javaExtractRoutes = h.java.ExtractRoutes
	h.nodeExtractRoutes = ExtractNodejsRoutes

	return h
}

func (h *RouteHarvester) HarvestRoutes(fileInfo *exec.FileInfo) (*RouteHarvesterResult, error) {
	// Ensure we harvest one by one
	h.mux.Lock()
	defer h.mux.Unlock()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	// Channel to receive the result
	type result struct {
		r   *RouteHarvesterResult
		err error
	}

	resultChan := make(chan result, 1)

	// We need to fix this in the downstream library and then we can remove this code
	if fileInfo.Service.SDKLanguage == svc.InstrumentableJava {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		h.java.Attacher.Init()
		defer h.java.Attacher.Cleanup()
	}

	// Run the harvesting in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				h.log.Error("route harvesting failed", "error", r)
				resultChan <- result{err: &HarvestError{Message: "harvesting failed"}}
			}
		}()

		switch fileInfo.Service.SDKLanguage {
		case svc.InstrumentableJava:
			if _, ok := h.disabled[svc.InstrumentableJava]; !ok {
				r, err := h.javaExtractRoutes(fileInfo.Pid)
				if err != nil {
					resultChan <- result{err: err}
					return
				}
				resultChan <- result{r: r}
			} else {
				resultChan <- result{r: nil}
			}
		case svc.InstrumentableNodejs:
			if _, ok := h.disabled[svc.InstrumentableNodejs]; !ok {
				r, err := h.nodeExtractRoutes(fileInfo.Pid)
				if err != nil {
					resultChan <- result{err: err}
					return
				}
				h.log.Debug("found node js application routes", "routes", r.Routes)

				resultChan <- result{r: r}
			} else {
				resultChan <- result{r: nil}
			}
		default:
			resultChan <- result{r: nil}
		}
	}()

	// Wait for either completion or timeout
	select {
	case result := <-resultChan:
		return result.r, result.err
	case <-ctx.Done():
		h.log.Warn("route harvesting timed out", "timeout", h.timeout, "pid", fileInfo.Pid)
		return nil, &HarvestError{Message: "route harvesting timed out"}
	}
}

func RouteMatcherFromResult(r RouteHarvesterResult) route.Matcher {
	switch r.Kind {
	case CompleteRoutes:
		return route.NewMatcher(r.Routes)
	case PartialRoutes:
		return route.NewPartialRouteMatcher(r.Routes)
	}

	return nil
}

func (h *RouteHarvester) HarvestRoutesDelay(fileInfo *exec.FileInfo) (bool, time.Duration) {
	if fileInfo.Service.SDKLanguage == svc.InstrumentableJava {
		return true, h.cfg.JavaHarvestDelay
	}

	return false, 0
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// for testing purposes
var isDirFunc = isDir

func FindScriptDirectory(root, firstArg, cwd string) string {
	if strings.HasPrefix(firstArg, "/") {
		path := filepath.Join(root, firstArg)
		if isDirFunc(path) {
			return path + string(filepath.Separator)
		}

		lastSlashPos := strings.LastIndex(firstArg, "/")
		if lastSlashPos > 1 {
			path := filepath.Join(root, firstArg[:lastSlashPos])

			if isDirFunc(path) {
				return path + string(filepath.Separator)
			}
		}
	}

	result := filepath.Join(root, cwd)
	if result != "" && result[len(result)-1] != filepath.Separator {
		result += string(filepath.Separator)
	}

	return result
}
