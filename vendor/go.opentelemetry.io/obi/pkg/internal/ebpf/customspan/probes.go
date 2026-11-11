// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package customspan // import "go.opentelemetry.io/obi/pkg/internal/ebpf/customspan"

import (
	"debug/elf"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

type Programs struct {
	Start  *ebpf.Program
	End    *ebpf.Program
	Single *ebpf.Program
	Specs  *ebpf.Map
	IPs    *ebpf.Map
}

func (r *Runtime) Descriptors(span *config.CustomSpanSpec, cookie uint64, programs Programs) []*ebpfcommon.USDTProbeDesc {
	if span.IsAnyFunction() {
		probe := r.functionModeProbe(span, cookie, programs)
		// Give overlapping generations at the same file offset distinct spec keys.
		probe.RewriteSpec = func(v any) (any, error) { return v, nil }
		return []*ebpfcommon.USDTProbeDesc{probe}
	}
	rewrite := obiebpf.MakeCustomSpanSpecRewrite(span, cookie)
	makeProbe := func(ident string, program *ebpf.Program) *ebpfcommon.USDTProbeDesc {
		provider, name, _ := strings.Cut(ident, ":")
		return &ebpfcommon.USDTProbeDesc{
			Provider:    provider,
			Name:        name,
			Program:     program,
			SpecsMap:    programs.Specs,
			IPMap:       programs.IPs,
			SpecManager: r.specManager,
			Cookie:      cookie,
			RewriteSpec: rewrite,
		}
	}
	if span.IsUSDTSpan() {
		return []*ebpfcommon.USDTProbeDesc{makeProbe(span.USDTStartProbe(), programs.Start), makeProbe(span.USDTEndProbe(), programs.End)}
	}
	return []*ebpfcommon.USDTProbeDesc{makeProbe(span.USDTNoRetProbe(), programs.Single)}
}

func (r *Runtime) functionModeProbe(span *config.CustomSpanSpec, cookie uint64,
	programs Programs,
) *ebpfcommon.USDTProbeDesc {
	isPaired := span.IsFunctionSpan()
	entryProg := programs.Single
	var retProg *ebpf.Program
	if isPaired {
		entryProg = programs.Start
		retProg = programs.End
	}
	builder := func(elfFile any) (any, error) {
		ef, _ := elfFile.(*elf.File)
		lang := obiebpf.FunctionLangC
		if ef != nil {
			lang = obiebpf.DetectFunctionLang(ef)
		}
		var (
			compiled obiebpf.CompiledCustomSpanSpec
			err      error
		)
		autoOK := false
		if lang == obiebpf.FunctionLangGo && ef != nil {
			var slots []obiebpf.AutoAttrSlot
			compiled, slots, err = obiebpf.BuildFunctionAutoSpec(ef, span, cookie, runtime.GOARCH)
			if err != nil {
				compiled, slots, err = obiebpf.BuildFunctionDWARFSpec(ef, span, cookie, runtime.GOARCH)
			}
			if err != nil {
				r.log.Debug("custom_span: auto attr extraction unavailable",
					"span", span.Name, "error", err)
			} else {
				autoOK = true
				if len(span.Attrs) > 0 {
					manual, mErr := obiebpf.BuildFunctionABISpec(span, cookie, runtime.GOARCH, lang)
					if mErr != nil {
						err = mErr
					} else {
						compiled, slots = obiebpf.MergeManualOverAuto(compiled, manual, slots)
					}
				}
				if err == nil {
					r.registry.SetAutoSlots(cookie, slots)
				}
			}
		}
		if !autoOK {
			compiled, err = obiebpf.BuildFunctionABISpec(span, cookie, runtime.GOARCH, lang)
		}
		if err != nil {
			return nil, err
		}
		// Goroutines can move between OS threads during a call.
		if lang == obiebpf.FunctionLangGo {
			compiled.Spec.PairKind = obiebpf.ObiUSDTPairG()
		} else {
			compiled.Spec.PairKind = obiebpf.ObiUSDTPairTid()
		}
		return compiled.Spec, nil
	}
	return &ebpfcommon.USDTProbeDesc{
		Function:          span.FunctionSymbol(),
		BuildFunctionSpec: builder,
		Program:           entryProg,
		ReturnProgram:     retProg,
		SpecsMap:          programs.Specs,
		IPMap:             programs.IPs,
		SpecManager:       r.specManager,
		Cookie:            cookie,
	}
}
