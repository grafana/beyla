// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"context"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type instrumenter struct{}

// dummy implementations to avoid compilation errors in Darwin.
// The tracer component is only usable in Linux.

func (pt *ProcessTracer) Run(
	ctx context.Context,
	_ *ebpfcommon.EBPFEventContext,
	_ *msg.Queue[[]request.Span],
) {
	// avoids linter complaining for not using metrics
	pt.metrics.Start(ctx)
}

func NewProcessTracer(_ ProcessTracerType, _ []Tracer, _ *obi.Config, _ imetrics.Reporter) *ProcessTracer {
	return nil
}

func (pt *ProcessTracer) Init(_ *ebpfcommon.EBPFEventContext, _ *obi.Config) error {
	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()

	pt.log.Debug("avoiding linter complaints for fields only used by the Linux tracer",
		"v", pt.shutdownTimeout, "bpffsPath", pt.bpffsPath,
		"executableGeneration", pt.nextExecutableGeneration,
		"instrumentableGenerations", pt.instrumentableGenerations,
		"goInstrumentablesByInode", pt.goInstrumentablesByInode)
	return nil
}

func (pt *ProcessTracer) NewExecutable(_ *link.Executable, _ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) NewExecutableInstance(_ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(_ *exec.FileInfo, _ uint64) {}

func RunUtilityTracer(_ context.Context, _ *ebpfcommon.EBPFEventContext, _ UtilityTracer, _ *obi.Config) error {
	return nil
}
