// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

type instrumentedExecutable struct {
	Type                 svc.InstrumentableType
	Offsets              *goexec.Offsets
	InstrumentationError error
}

// ExecTyperProvider classifies the discovered executables according to the
// executable type (Go, generic...), and filters these executables
// that are not instrumentable.
func ExecTyperProvider(
	cfg *obi.Config,
	metrics imetrics.Reporter,
	k8sInformer *kube.MetadataProvider,
	input *msg.Queue[[]Event[ProcessMatch]],
	output *msg.Queue[[]Event[ebpf.Instrumentable]],
) swarm.InstanceFunc {
	instrumentableCache, _ := lru.New[uint64, instrumentedExecutable](100)

	t := typer{
		cfg:                 cfg,
		metrics:             metrics,
		k8sInformer:         k8sInformer,
		log:                 slog.With("component", "discover.ExecTyper"),
		currentPids:         map[int32]*exec.FileInfo{},
		instrumentableCache: instrumentableCache,
	}
	return func(_ context.Context) (swarm.RunFunc, error) {
		// TODO: do it per executable
		if !cfg.Discovery.SkipGoSpecificTracers {
			t.loadAllGoFunctionNames()
		}
		in := input.Subscribe(msg.SubscriberName("ExecTyper"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, t.log.Debug, func(i []Event[ProcessMatch]) {
				output.Send(t.FilterClassify(i))
			})
		}, nil
	}
}

type typer struct {
	cfg                 *obi.Config
	metrics             imetrics.Reporter
	k8sInformer         *kube.MetadataProvider
	log                 *slog.Logger
	currentPids         map[int32]*exec.FileInfo
	allGoFunctions      []string
	instrumentableCache *lru.Cache[uint64, instrumentedExecutable]
}

func samplerFromConfig(s *services.SamplerConfig) trace.Sampler {
	if s != nil {
		return s.Implementation()
	}

	return nil
}

func makeServiceAttrs(processMatch *ProcessMatch) svc.Attrs {
	var name string
	var namespace string
	exportModes := services.ExportModeUnset
	var samplerConfig *services.SamplerConfig
	var routesConfig *services.CustomRoutesConfig

	for _, s := range processMatch.Criteria {
		if n := s.GetName(); n != "" {
			name = n
		}

		if n := s.GetNamespace(); n != "" {
			namespace = n
		}

		if m := s.GetExportModes(); m != services.ExportModeUnset {
			exportModes = m
		}

		if m := s.GetSamplerConfig(); m != nil {
			samplerConfig = m
		}

		if m := s.GetRoutesConfig(); m != nil {
			routesConfig = m
		}
	}

	s := svc.Attrs{
		UID: svc.UID{
			Name:      name,
			Namespace: namespace,
		},
		ProcPID:     processMatch.Process.Pid,
		ExportModes: exportModes,
		Sampler:     samplerFromConfig(samplerConfig),
	}

	if routesConfig != nil {
		s.SetCustomRoutes(routesConfig)
	}

	return s
}

// FilterClassify returns the Instrumentable types for each received ProcessMatch,
// and filters out the processes that can't be instrumented (e.g. because of the lack
// of instrumentation points)
func (t *typer) FilterClassify(evs []Event[ProcessMatch]) []Event[ebpf.Instrumentable] {
	var out []Event[ebpf.Instrumentable]

	elfs := make([]*exec.FileInfo, 0, len(evs))
	// Update first the PID map so we use only the parent processes
	// in case of multiple matches
	for i := range evs {
		ev := &evs[i]
		switch evs[i].Type {
		case EventCreated:
			svcID := makeServiceAttrs(&ev.Obj)

			if elfFile, err := findExecElf(ev.Obj.Process, svcID, t.k8sInformer.IsKubeEnabled()); err != nil {
				t.log.Debug("error finding process ELF. Ignoring", "error", err)
			} else {
				t.currentPids[ev.Obj.Process.Pid] = elfFile
				elfs = append(elfs, elfFile)
			}
		case EventDeleted:
			if fInfo, ok := t.currentPids[ev.Obj.Process.Pid]; ok {
				delete(t.currentPids, ev.Obj.Process.Pid)
				out = append(out, Event[ebpf.Instrumentable]{
					Type: EventDeleted,
					Obj:  ebpf.Instrumentable{FileInfo: fInfo},
				})
			}
		}
	}

	for i := range elfs {
		inst := t.asInstrumentable(elfs[i])
		t.log.Debug(
			"found an instrumentable process",
			"UID", inst.FileInfo.Service.UID,
			"type", inst.Type.String(),
			"exec", inst.FileInfo.CmdExePath, "pid", inst.FileInfo.Pid)
		out = append(out, Event[ebpf.Instrumentable]{Type: EventCreated, Obj: inst})
	}
	return out
}

// asInstrumentable classifies the type of executable (Go, generic...) and,
// in case of belonging to a forked process, returns its parent.
func (t *typer) asInstrumentable(execElf *exec.FileInfo) ebpf.Instrumentable {
	log := t.log.With("pid", execElf.Pid, "comm", execElf.CmdExePath)
	if ic, ok := t.instrumentableCache.Get(execElf.Ino); ok {
		log.Debug("new instance of existing executable", "type", ic.Type)
		return ebpf.Instrumentable{Type: ic.Type, FileInfo: execElf, Offsets: ic.Offsets, InstrumentationError: ic.InstrumentationError}
	}

	log.Debug("getting instrumentable information")
	// look for suitable Go application first
	offsets, ok, err := t.inspectOffsets(execElf)
	if ok {
		// we found go offsets, let's see if this application is not a proxy
		if !isGoProxy(offsets) {
			log.Debug("identified as a Go service or client")
			t.instrumentableCache.Add(execElf.Ino, instrumentedExecutable{Type: svc.InstrumentableGolang, Offsets: offsets})
			return ebpf.Instrumentable{Type: svc.InstrumentableGolang, FileInfo: execElf, Offsets: offsets}
		}

		if err == nil {
			err = errors.New("identified as a Go proxy")
		}

		log.Debug("identified as a Go proxy")
	} else {
		log.Debug("identified as a generic, non-Go executable")
	}

	// select the parent (or grandparent) of the executable, if any
	var child []uint32
	parent, ok := t.currentPids[execElf.Ppid]
	for ok && execElf.Ppid != execElf.Pid &&
		// we will ignore parent processes that are not the same executable. For example,
		// to avoid wrongly instrumenting process launcher such as systemd or containerd-shimd
		// when they launch an instrumentable service
		execElf.CmdExePath == parent.CmdExePath {
		log.Debug("replacing executable by its parent", "ppid", execElf.Ppid)
		child = append(child, uint32(execElf.Pid))
		execElf = parent
		parent, ok = t.currentPids[parent.Ppid]
	}

	detectedType := procs.FindProcLanguage(execElf.Pid)

	if detectedType == svc.InstrumentableGolang && err == nil {
		log.Warn("ELF binary appears to be a Go program, but no offsets were found",
			"comm", execElf.CmdExePath, "pid", execElf.Pid)

		err = fmt.Errorf("could not find any Go offsets in Go binary %s", execElf.CmdExePath)
	}

	log.Debug("instrumented", "comm", execElf.CmdExePath, "pid", execElf.Pid,
		"child", child, "language", detectedType.String())
	// Return the instrumentable without offsets, as it is identified as a generic
	// (or non-instrumentable Go proxy) executable
	t.instrumentableCache.Add(execElf.Ino, instrumentedExecutable{Type: detectedType, Offsets: nil, InstrumentationError: err})
	return ebpf.Instrumentable{Type: detectedType, Offsets: nil, FileInfo: execElf, ChildPids: child, InstrumentationError: err}
}

func (t *typer) inspectOffsets(execElf *exec.FileInfo) (*goexec.Offsets, bool, error) {
	if t.cfg.Discovery.SkipGoSpecificTracers {
		t.log.Debug("skipping inspection for Go functions", "pid", execElf.Pid, "comm", execElf.CmdExePath)
		return nil, false, nil
	}
	t.log.Debug("inspecting", "pid", execElf.Pid, "comm", execElf.CmdExePath)
	offsets, err := goexec.InspectOffsets(execElf, t.allGoFunctions)
	if err != nil {
		t.log.Debug("couldn't find go specific tracers", "error", err)
		return nil, false, err
	}
	return offsets, true, nil
}

func isGoProxy(offsets *goexec.Offsets) bool {
	for f := range offsets.Funcs {
		// if we find anything of interest other than the Go runtime, we consider this a valid application
		if !strings.HasPrefix(f, "runtime.") {
			return false
		}
	}

	return true
}

func (t *typer) loadAllGoFunctionNames() {
	uniqueFunctions := map[string]struct{}{}
	t.allGoFunctions = nil
	for _, p := range newGoTracersGroup(nil, t.cfg, t.metrics) {
		for symbolName := range p.GoProbes() {
			// avoid duplicating function names
			if _, ok := uniqueFunctions[symbolName]; !ok {
				uniqueFunctions[symbolName] = struct{}{}
				t.allGoFunctions = append(t.allGoFunctions, symbolName)
			}
		}
	}
}
