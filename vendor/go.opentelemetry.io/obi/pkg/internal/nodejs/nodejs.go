// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	_ "embed"
	"errors"
	"log/slog"
	"syscall"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
)

type NodeInjector struct {
	log *slog.Logger
	cfg *obi.Config
}

func NewNodeInjector(cfg *obi.Config) *NodeInjector {
	return &NodeInjector{
		cfg: cfg,
		log: slog.With("component", "nodejs.Injector"),
	}
}

func (i *NodeInjector) Enabled() bool {
	return i.cfg.NodeJS.Enabled && (i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled())
}

func (i *NodeInjector) NewExecutable(ie *ebpf.Instrumentable) {
	if !i.Enabled() {
		i.log.Debug("Node Injector is disabled")
		return
	}

	if ie.Type != svc.InstrumentableNodejs {
		i.log.Debug("not a NodeJS executable")
		return
	}

	i.log.Info("loading NodeJS instrumentation", "pid", ie.FileInfo.Pid)

	if err := i.attachAgent(int(ie.FileInfo.Pid)); err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", ie.FileInfo.Pid, "error", err)
		i.log.Error("trace-context propagation will not work for NodeJS services!")
	}
}

func (i *NodeInjector) attachAgent(pid int) error {
	err := syscall.Kill(pid, syscall.SIGUSR1)
	if err != nil {
		i.log.Error("error enabling node inspector", "err", err)
		return errors.New("error enabling node inspector")
	}

	return i.inject(pid)
}

//go:embed fdextractor.js
var _extractorBytes []byte
