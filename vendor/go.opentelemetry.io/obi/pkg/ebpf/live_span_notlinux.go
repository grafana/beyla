// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"debug/elf"
	"errors"
	"io"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

func (pt *ProcessTracer) AttachLiveSpan(app.PID, uint32, *config.CustomSpanSpec, uint64, string, uint64) (io.Closer, error) {
	return nil, errors.New("live probes require Linux")
}

type SymbolCache struct{}

func NewSymbolCache(config.DynamicInstrumentationConfig) *SymbolCache {
	return &SymbolCache{}
}

func (*SymbolCache) ResolveLiveSymbols(app.PID, string) ([]string, error) {
	return nil, errors.New("symbol resolution requires Linux")
}

func (pt *ProcessTracer) ResolveLiveSymbols(_ app.PID, _ string) ([]string, error) {
	return nil, errors.New("dynamic probes require Linux")
}

func AddSDKContextOffsets(_ *elf.File, _ *goexec.Offsets) {}

func (pt *ProcessTracer) RegisterJavaSpan(app.PID, *config.CustomSpanSpec, uint64, string, uint64) (io.Closer, error) {
	return nil, errors.New("java dynamic probes require Linux")
}
