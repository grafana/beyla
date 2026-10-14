// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/denotools"
	"go.opentelemetry.io/obi/pkg/internal/dotnettools"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools"
	"go.opentelemetry.io/obi/pkg/internal/nodejstools"
	"go.opentelemetry.io/obi/pkg/internal/phptools"
	"go.opentelemetry.io/obi/pkg/internal/pythontools"
	"go.opentelemetry.io/obi/pkg/internal/rubytools"
)

// ProcessResourceDetector finds resources like the service.name, service.namespace and service.version,
// from the process binary or the process deployment directory.
type ProcessResourceDetector struct {
	log *slog.Logger
}

func NewProcessResourceDetector() *ProcessResourceDetector {
	return &ProcessResourceDetector{
		log: slog.With("component", "process.resource.detector"),
	}
}

func (r *ProcessResourceDetector) ResolveMetadata(t svc.InstrumentableType, fi *exec.FileInfo) {
	if fi == nil {
		return
	}
	var err error
	switch t {
	case svc.InstrumentableJava:
		err = jvmtools.ResolveServiceMetadata(fi)
	case svc.InstrumentableNodejs:
		err = nodejstools.ResolveServiceMetadata(fi)
	case svc.InstrumentablePython:
		err = pythontools.ResolveServiceMetadata(fi)
	case svc.InstrumentableDotnet:
		err = dotnettools.ResolveServiceMetadata(fi)
	case svc.InstrumentableDeno:
		err = denotools.ResolveServiceMetadata(fi)
	case svc.InstrumentableRuby:
		err = rubytools.ResolveServiceMetadata(fi)
	case svc.InstrumentablePHP:
		err = phptools.ResolveServiceMetadata(fi)
	}
	if err != nil {
		r.log.Debug("unable to resolve service metadata", "type", t, "pid", fi.Pid(), "error", err)
	}
}
