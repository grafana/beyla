// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"log/slog"
	"strings"

	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/components/transform/route"
)

type RouteHarvester struct {
	log      *slog.Logger
	java     *JavaRoutes
	disabled map[svc.InstrumentableType]struct{}
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

func NewRouteHarvester(disabled []string) *RouteHarvester {
	dMap := map[svc.InstrumentableType]struct{}{}
	for _, lang := range disabled {
		if strings.ToLower(lang) == "java" {
			dMap[svc.InstrumentableJava] = struct{}{}
		}
	}

	return &RouteHarvester{
		log:      slog.With("component", "route.harvester"),
		java:     NewJavaRoutesHarvester(),
		disabled: dMap,
	}
}

func (h *RouteHarvester) HarvestRoutes(fileInfo *exec.FileInfo) (*RouteHarvesterResult, error) {
	if fileInfo.Service.SDKLanguage == svc.InstrumentableJava {
		if _, ok := h.disabled[svc.InstrumentableJava]; !ok {
			return h.java.ExtractRoutes(fileInfo.Pid)
		}
	}

	return nil, nil
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
