// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/clusterurl"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// Swappable in tests so typer tests don't depend on /proc inspections.
var findProcLanguage = procs.FindProcLanguage

type cacheKey struct {
	Dev        uint64
	Ino        uint64
	ChangeTime int64
}

func executableCacheKey(info *exec.FileInfo) cacheKey {
	return cacheKey{Dev: info.Dev(), Ino: info.Ino(), ChangeTime: info.ChangeTime()}
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
	goOffsetsCache, _ := lru.New[cacheKey, goInspectionResult](100)

	t := typer{
		cfg:            cfg,
		metrics:        metrics,
		k8sInformer:    k8sInformer,
		log:            slog.With("component", "discover.ExecTyper"),
		currentPids:    map[app.PID]*exec.FileInfo{},
		goOffsetsCache: goOffsetsCache,
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

type goInspectionResult struct {
	offsets *goexec.Offsets
	err     error
}

type typer struct {
	cfg            *obi.Config
	metrics        imetrics.Reporter
	k8sInformer    *kube.MetadataProvider
	log            *slog.Logger
	currentPids    map[app.PID]*exec.FileInfo
	allGoFunctions []string
	goOffsetsCache *lru.Cache[cacheKey, goInspectionResult]
}

func samplerFromConfig(s *services.SamplerConfig) trace.Sampler {
	if s != nil {
		return s.Implementation()
	}

	return nil
}

func selectorExceptions(selector services.Selector) *services.ExceptionsOverride {
	if provider, ok := selector.(interface {
		GetExceptionsConfig() *services.ExceptionsOverride
	}); ok {
		return provider.GetExceptionsConfig()
	}
	return nil
}

func (t *typer) makeServiceAttrs(processMatch *ProcessMatch) svc.Attrs {
	name := t.cfg.ServiceName
	namespace := t.cfg.ServiceNamespace
	exportModes := services.ExportModeUnset
	samplerConfig := samplingConfig(*processMatch)
	var routesConfig *services.CustomRoutesConfig
	svcFeatures := t.cfg.Metrics.Features
	exceptions := t.cfg.Exceptions
	var metadata map[attr.Name]string

	for _, s := range processMatch.Criteria {
		if n := s.GetName(); n != "" {
			name = n
		}

		if n := s.GetNamespace(); n != "" {
			namespace = n
		}

		if m := ResourceAttributesFromSelector(s); len(m) > 0 {
			if metadata == nil {
				metadata = make(map[attr.Name]string, len(m))
			}
			maps.Copy(metadata, m)
		}

		if m := s.GetExportModes(); m != services.ExportModeUnset {
			exportModes = m
		}

		if m := s.GetRoutesConfig(); m != nil {
			routesConfig = m
		}

		exceptions = selectorExceptions(s).Resolve(t.cfg.Exceptions)

		// if the matching service > instrument entry does not define features,
		// the globally defined features apply (and override any previous,
		// wider-scope match features)
		svcFeatures = s.MetricsConfig().Features
		if svcFeatures.Undefined() {
			svcFeatures = t.cfg.Metrics.Features
		}
	}

	s := svc.Attrs{
		UID: svc.UID{
			Name:      name,
			Namespace: namespace,
		},
		Metadata:           metadata,
		ProcPID:            processMatch.Process.Pid,
		DynamicSelectorPID: processMatch.DynamicSelectorPID,
		ExportModes:        exportModes,
		Sampler:            samplerFromConfig(samplerConfig),
		SamplerConfig:      samplerConfig,
		Features:           svcFeatures,
		LogEnricherEnabled: processMatch.LogEnricherEnabled(),
		Exceptions:         exceptions,
		SDKLanguage:        svc.InstrumentableGeneric,
	}

	s.Exceptions.Enabled = s.Exceptions.Enabled && s.ExportModes.CanExportLogs() && t.cfg.Logs.Enabled()

	routesCfg := t.cfg.Routes
	if routesCfg != nil && routesCfg.Directional != nil {
		policies := routesCfg.DirectionalPolicies()
		var overrides *services.DirectionalRoutePolicyOverrides
		if routesConfig != nil {
			overrides = routesConfig.PolicyOverrides
		}
		if routesCfg.DirectionalRuleOnly {
			if overrides == nil {
				return s
			}
			if overrides.Incoming != nil {
				s.IncomingRoutePolicy = svc.NewRoutePolicy(
					overrides.Incoming.Apply(policies.Incoming))
			}
			if overrides.Outgoing != nil {
				s.OutgoingRoutePolicy = svc.NewRoutePolicy(
					overrides.Outgoing.Apply(policies.Outgoing))
			}
			return s
		}
		if overrides != nil && overrides.Incoming != nil {
			s.IncomingRoutePolicy = svc.NewRoutePolicy(overrides.Incoming.Apply(policies.Incoming))
		} else if routesCfg.HasIncomingPolicy() {
			s.IncomingPathTrie = svc.NewRoutePathTrie(policies.Incoming)
		}
		if overrides != nil && overrides.Outgoing != nil {
			s.OutgoingRoutePolicy = svc.NewRoutePolicy(overrides.Outgoing.Apply(policies.Outgoing))
		} else if routesCfg.HasOutgoingPolicy() {
			s.OutgoingPathTrie = svc.NewRoutePathTrie(policies.Outgoing)
		}
		return s
	}

	wildcard := byte('*')
	maxPathSegmentCardinality := 0
	if routesCfg != nil {
		maxPathSegmentCardinality = routesCfg.MaxPathSegmentCardinality
		if routesCfg.WildcardChar != "" {
			wildcard = routesCfg.WildcardChar[0]
		}
	}
	s.PathTrie = clusterurl.NewPathTrie(maxPathSegmentCardinality, wildcard)
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
	// Record the whole batch before looking up ancestors.
	for i := range evs {
		ev := &evs[i]
		switch evs[i].Type {
		case EventUpdated:
			if fInfo, ok := t.currentPids[ev.Obj.Process.Pid]; ok {
				out = append(out, Event[ebpf.Instrumentable]{
					Type: EventUpdated,
					Obj:  ebpf.Instrumentable{FileInfo: fInfo, SamplerConfig: samplingConfig(ev.Obj)},
				})
			}
		case EventCreated:
			svcID := t.makeServiceAttrs(&ev.Obj)

			if elfFile, err := findExecElf(ev.Obj.Process, &svcID); err != nil {
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
			"UID", inst.FileInfo.ServiceAttrs().UID,
			"type", inst.Type.String(),
			"exec", inst.FileInfo.CmdExePath(), "pid", inst.FileInfo.Pid())
		out = append(out, Event[ebpf.Instrumentable]{Type: EventCreated, Obj: inst})
	}
	return out
}

// asInstrumentable classifies the discovered process.
func (t *typer) asInstrumentable(execElf *exec.FileInfo) ebpf.Instrumentable {
	log := t.log.With("pid", execElf.Pid(), "comm", execElf.CmdExePath())
	key := executableCacheKey(execElf)
	result, cached := t.goOffsetsCache.Get(key)
	if !cached {
		result.offsets, result.err = t.inspectOffsets(execElf)
		if result.offsets != nil || errors.Is(result.err, goexec.ErrNoInstrumentationPoints) || errors.Is(result.err, goexec.ErrUnsupportedGoVersion) {
			t.goOffsetsCache.Add(key, result)
		}
	}
	offsets, err := result.offsets, result.err
	if offsets != nil && isGoProxy(offsets) {
		log.Debug("identified as a Go proxy")
		offsets = nil
		err = errors.New("identified as a Go proxy")
	}
	if offsets != nil {
		return ebpf.Instrumentable{
			Type: svc.InstrumentableGolang, FileInfo: execElf, Offsets: offsets,
			LogEnricherEnabled: execElf.LogEnricherEnabled(),
		}
	}
	// Path and port selectors can match processes the language decorator skipped.
	detectedType, languageErr := findProcLanguage(execElf.Pid())
	if languageErr != nil || detectedType == svc.InstrumentablePython {
		ancestor := execElf
		for {
			parent := t.currentPids[ancestor.Ppid()]
			if parent == nil || parent.Pid() == ancestor.Pid() || parent.CmdExePath() != ancestor.CmdExePath() {
				break
			}
			ancestor = parent
		}
		if ancestor != execElf {
			parentType, parentErr := findProcLanguage(ancestor.Pid())
			if languageErr != nil && parentErr == nil {
				// A short-lived worker can disappear before inspection.
				detectedType, languageErr = parentType, nil
			}
			if detectedType == svc.InstrumentablePython && parentType == detectedType && parentErr == nil {
				execElf.SetRuntimeMetricServiceSource(ancestor)
			}
		}
	}
	if detectedType != svc.InstrumentableGolang {
		// A non-Go process does not need Go offsets. Its classification succeeded
		// if its language could be inspected before the process exited.
		err = languageErr
	}

	if !t.cfg.Discovery.SkipGoSpecificTracers && detectedType == svc.InstrumentableGolang && err == nil {
		log.Warn("ELF binary appears to be a Go program, but no offsets were found",
			"comm", execElf.CmdExePath(), "pid", execElf.Pid())

		err = fmt.Errorf("could not find any Go offsets in Go binary %s", execElf.CmdExePath())
	}

	log.Debug("instrumented", "comm", execElf.CmdExePath(), "pid", execElf.Pid(), "language", detectedType.String())
	return ebpf.Instrumentable{
		Type:                 detectedType,
		FileInfo:             execElf,
		InstrumentationError: err,
		LogEnricherEnabled:   execElf.LogEnricherEnabled(),
	}
}

func (t *typer) inspectOffsets(execElf *exec.FileInfo) (*goexec.Offsets, error) {
	if t.cfg.Discovery.SkipGoSpecificTracers {
		t.log.Debug("skipping inspection for Go functions", "pid", execElf.Pid(), "comm", execElf.CmdExePath())
		return nil, nil
	}
	if execElf.ELF() == nil || execElf.ELF().Section(".gopclntab") == nil {
		return nil, nil
	}
	t.log.Debug("inspecting", "pid", execElf.Pid(), "comm", execElf.CmdExePath())
	offsets, err := goexec.InspectOffsets(execElf, t.allGoFunctions)
	if err != nil {
		t.log.Debug("couldn't find go specific tracers", "error", err)
		return nil, err
	}
	return offsets, nil
}

// Symbols probed only to support other instrumentation: present in almost any
// Go executable, they don't make it a Go service
var supportOnlyGoProbeSymbols = func() map[string]struct{} {
	symbols := map[string]struct{}{"context.WithValue": {}}
	for _, symbol := range gotracer.GoExceptionProbeSymbols() {
		symbols[symbol] = struct{}{}
	}
	return symbols
}()

func isGoProxy(offsets *goexec.Offsets) bool {
	for f := range offsets.Funcs {
		if strings.HasPrefix(f, "runtime.") {
			continue
		}
		if _, ok := supportOnlyGoProbeSymbols[f]; ok {
			continue
		}

		return false
	}

	return true
}

func (t *typer) loadAllGoFunctionNames() {
	uniqueFunctions := map[string]struct{}{}
	t.allGoFunctions = nil
	for _, p := range newGoTracersGroup(nil, t.cfg, t.metrics) {
		for symbolName := range p.GoProbes() {
			t.addGoFunctionName(uniqueFunctions, symbolName)
		}
	}

	for _, symbolName := range gotracer.GoChannelLinkProbeSymbols() {
		t.addGoFunctionName(uniqueFunctions, symbolName)
	}
	for _, symbolName := range gotracer.GoRuntimeMetricProbeSymbols() {
		t.addGoFunctionName(uniqueFunctions, symbolName)
	}
	for _, symbolName := range gotracer.GoAutoSDKActivationProbeSymbols() {
		t.addGoFunctionName(uniqueFunctions, symbolName)
	}
	for _, symbolName := range gotracer.GoHTTP2FlushProbeSymbols() {
		t.addGoFunctionName(uniqueFunctions, symbolName)
	}
	for _, symbolName := range gotracer.GoH2OwnershipProbeSymbols() {
		t.addGoFunctionName(uniqueFunctions, symbolName)
	}
	if t.cfg.ExceptionsEnabled() && t.cfg.Logs.Enabled() {
		for _, symbolName := range gotracer.GoExceptionProbeSymbols() {
			t.addGoFunctionName(uniqueFunctions, symbolName)
		}
	}
}

func (t *typer) addGoFunctionName(uniqueFunctions map[string]struct{}, symbolName string) {
	if _, ok := uniqueFunctions[symbolName]; ok {
		return
	}

	uniqueFunctions[symbolName] = struct{}{}
	t.allGoFunctions = append(t.allGoFunctions, symbolName)
}
