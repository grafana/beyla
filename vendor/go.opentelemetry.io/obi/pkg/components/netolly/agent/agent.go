// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/components/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/netolly/flow"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const (
	listenPoll       = "poll"
	listenWatch      = "watch"
	directionIngress = "ingress"
	directionEgress  = "egress"
	directionBoth    = "both"

	ipTypeAny  = "any"
	ipTypeIPV4 = "ipv4"
	ipTypeIPV6 = "ipv6"

	ipIfaceExternal    = "external"
	ipIfaceLocal       = "local"
	ipIfaceNamedPrefix = "name:"
)

func alog() *slog.Logger {
	return slog.With("component", "agent.Flows")
}

// Status of the agent service. Helps on the health report as well as making some asynchronous
// tests waiting for the agent to accept flows.
type Status int

const (
	StatusNotStarted Status = iota
	StatusStarting
	StatusStarted
	StatusStopping
	StatusStopped
)

func (s Status) String() string {
	switch s {
	case StatusNotStarted:
		return "StatusNotStarted"
	case StatusStarting:
		return "StatusStarting"
	case StatusStarted:
		return "StatusStarted"
	case StatusStopping:
		return "StatusStopping"
	case StatusStopped:
		return "StatusStopped"
	default:
		return "invalid"
	}
}

var errShutdownTimeout = errors.New("graceful shutdown has timed out while waiting for eBPF network infrastructure to finish")

// Flows reporting agent
type Flows struct {
	cfg     *obi.Config
	ctxInfo *global.ContextInfo
	graph   *swarm.Runner

	// input data providers
	ifaceManager *tcmanager.InterfaceManager
	ebpf         ebpfFlowFetcher

	// processing nodes to be wired in the buildPipeline method
	rbTracer *flow.RingBufTracer

	// elements used to decorate flows with extra information
	interfaceNamer flow.InterfaceNamer
	agentIP        net.IP

	status Status
}

// ebpfFlowFetcher abstracts the interface of ebpf.FlowFetcher to allow dependency injection in tests
type ebpfFlowFetcher interface {
	io.Closer

	ReadInto(*ringbuf.Record) error
}

// FlowsAgent instantiates a new agent, given a configuration.
func FlowsAgent(ctxInfo *global.ContextInfo, cfg *obi.Config) (*Flows, error) {
	alog := alog()
	alog.Info("initializing Flows agent")

	ifaceManager := tcmanager.NewInterfaceManager()
	ifaceManager.SetChannelBufferLen(cfg.ChannelBufferLen)
	ifaceManager.SetPollPeriod(cfg.NetworkFlows.ListenPollPeriod)
	ifaceManager.SetMonitorMode(monitorMode(cfg, alog))

	alog.Debug("acquiring Agent IP")

	agentIP, err := fetchAgentIP(&cfg.NetworkFlows)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}

	alog.Debug("agent IP: " + agentIP.String())

	fetcher, err := newFetcher(cfg, alog, ifaceManager)
	if err != nil {
		return nil, err
	}

	return flowsAgent(ctxInfo, cfg, fetcher, agentIP, ifaceManager)
}

func newFetcher(cfg *obi.Config, alog *slog.Logger, ifaceManager *tcmanager.InterfaceManager) (ebpfFlowFetcher, error) {
	switch cfg.NetworkFlows.Source {
	case obi.EbpfSourceSock:
		alog.Info("using socket filter for collecting network events")

		return ebpf.NewSockFlowFetcher(cfg.NetworkFlows.Sampling,
			cfg.NetworkFlows.CacheMaxFlows,
			cfg.NetworkFlows.RingBufferSize,
			cfg.NetworkFlows.RingBufferFlushPeriod,
			cfg.NetworkFlows.MaxFlowDuration,
			cfg.NetworkFlows.Protocols,
			cfg.NetworkFlows.ExcludeProtocols,
		)
	case obi.EbpfSourceTC:
		alog.Info("using kernel Traffic Control for collecting network events")
		ingress, egress := flowDirections(&cfg.NetworkFlows)

		return ebpf.NewFlowFetcher(cfg.NetworkFlows.Sampling,
			cfg.NetworkFlows.CacheMaxFlows,
			ingress,
			egress,
			ifaceManager,
			cfg.EBPF.TCBackend,
			cfg.NetworkFlows.RingBufferSize,
			cfg.NetworkFlows.RingBufferFlushPeriod,
			cfg.NetworkFlows.MaxFlowDuration,
			cfg.NetworkFlows.Protocols,
			cfg.NetworkFlows.ExcludeProtocols,
		)
	}

	return nil, errors.New("unknown network configuration eBPF source specified, allowed options are [tc, socket_filter]")
}

func monitorMode(cfg *obi.Config, alog *slog.Logger) tcmanager.MonitorMode {
	switch cfg.NetworkFlows.ListenInterfaces {
	case listenPoll:
		alog.Debug("listening for new interfaces: use polling",
			"period", cfg.NetworkFlows.ListenPollPeriod)

		return tcmanager.MonitorPoll
	case listenWatch:
		alog.Debug("listening for new interfaces: use watching")

		return tcmanager.MonitorWatch
	}

	alog.Warn("wrong interface listen method. Using file watcher as default",
		"providedValue", cfg.NetworkFlows.ListenInterfaces)

	return tcmanager.MonitorWatch
}

// flowsAgent is a private constructor with injectable dependencies, usable for tests
func flowsAgent(
	ctxInfo *global.ContextInfo,
	cfg *obi.Config,
	fetcher ebpfFlowFetcher,
	agentIP net.IP,
	ifaceManager *tcmanager.InterfaceManager,
) (*Flows, error) {
	// configure allow/deny interfaces filter
	filter, err := tcmanager.NewInterfaceFilter(cfg.NetworkFlows.Interfaces, cfg.NetworkFlows.ExcludeInterfaces)
	if err != nil {
		return nil, fmt.Errorf("configuring interface filters: %w", err)
	}

	ifaceManager.SetInterfaceFilter(filter)

	interfaceNamer := func(ifIndex int) string {
		iface, ok := ifaceManager.InterfaceName(ifIndex)
		if !ok {
			return "unknown"
		}
		return iface
	}

	rbTracer := flow.NewRingBufTracer(fetcher)

	return &Flows{
		ctxInfo:        ctxInfo,
		ebpf:           fetcher,
		ifaceManager:   ifaceManager,
		cfg:            cfg,
		rbTracer:       rbTracer,
		agentIP:        agentIP,
		interfaceNamer: interfaceNamer,
	}, nil
}

func flowDirections(cfg *obi.NetworkConfig) (ingress, egress bool) {
	switch cfg.Direction {
	case directionIngress:
		return true, false
	case directionEgress:
		return false, true
	case directionBoth:
		return true, true
	default:
		alog().Warn("unknown DIRECTION. Tracing both ingress and egress traffic",
			"direction", cfg.Direction)
		return true, true
	}
}

// Run a Flows agent
func (f *Flows) Run(ctx context.Context) error {
	alog := alog()

	f.status = StatusStarting
	alog.Info("starting Flows agent")

	graph, err := f.buildPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	f.graph = graph

	f.ifaceManager.Start(ctx)

	f.graph.Start(ctx, swarm.WithCancelTimeout(f.cfg.ShutdownTimeout))
	f.status = StatusStarted

	alog.Info("Flows agent successfully started")

	<-ctx.Done()

	if err := f.stop(); err != nil {
		return fmt.Errorf("failed to stop Flows agent: %w", err)
	}

	return nil
}

func (f *Flows) stop() error {
	alog := alog()

	stopped := make(chan error)
	go func() {
		f.status = StatusStopping
		alog.Info("stopping Flows agent")
		if err := f.ebpf.Close(); err != nil {
			alog.Warn("eBPF resources not correctly closed", "error", err)
		}

		alog.Debug("waiting for all nodes to finish their pending work")

		f.ifaceManager.Wait()
		<-f.graph.Done()
		f.status = StatusStopped

		if err := <-f.graph.Done(); err != nil {
			stopped <- err
		}
		close(stopped)

		alog.Info("Flows agent stopped")
	}()

	select {
	case <-time.After(f.cfg.ShutdownTimeout):
		return errShutdownTimeout
	case err := <-stopped:
		// err might be nil
		return err
	}
}

func (f *Flows) Status() Status {
	return f.status
}
