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
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/gavv/monotime"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/beyla/config"
	"github.com/grafana/beyla/pkg/beyla/flows/ebpf"
	flow2 "github.com/grafana/beyla/pkg/beyla/flows/flow"
	ifaces2 "github.com/grafana/beyla/pkg/beyla/flows/ifaces"
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

// Flows reporting agent
type Flows struct {
	cfg *config.AgentConfig

	// input data providers
	interfaces ifaces2.Informer
	filter     interfaceFilter
	ebpf       ebpfFlowFetcher

	// processing nodes to be wired in the buildAndStartPipeline method
	mapTracer *flow2.MapTracer
	rbTracer  *flow2.RingBufTracer
	accounter *flow2.Accounter
	exporter  node.TerminalFunc[[]*flow2.Record]

	// elements used to decorate flows with extra information
	interfaceNamer flow2.InterfaceNamer
	agentIP        net.IP

	status Status
}

// ebpfFlowFetcher abstracts the interface of ebpf.FlowFetcher to allow dependency injection in tests
type ebpfFlowFetcher interface {
	io.Closer
	Register(iface ifaces2.Interface) error

	LookupAndDeleteMap() map[flow2.RecordKey][]flow2.RecordMetrics
	ReadRingBuf() (ringbuf.Record, error)
}

// FlowsAgent instantiates a new agent, given a configuration.
func FlowsAgent(cfg *config.AgentConfig) (*Flows, error) {
	alog := alog()
	alog.Info("initializing Flows agent")

	// configure informer for new interfaces
	var informer ifaces2.Informer
	switch cfg.ListenInterfaces {
	case ListenPoll:
		alog.Debug("listening for new interfaces: use polling",
			"period", cfg.ListenPollPeriod)
		informer = ifaces2.NewPoller(cfg.ListenPollPeriod, cfg.BuffersLength)
	case ListenWatch:
		alog.Debug("listening for new interfaces: use watching")
		informer = ifaces2.NewWatcher(cfg.BuffersLength)
	default:
		alog.Warn("wrong interface listen method. Using file watcher as default",
			"providedValue", cfg.ListenInterfaces)
		informer = ifaces2.NewWatcher(cfg.BuffersLength)
	}

	alog.Debug("acquiring Agent IP")
	agentIP, err := fetchAgentIP(cfg)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}
	alog.Debug("agent IP: " + agentIP.String())

	// configure selected exporter
	exportFunc, err := buildFlowExporter(cfg)
	if err != nil {
		return nil, err
	}

	ingress, egress := flowDirections(cfg)

	fetcher, err := ebpf.NewFlowFetcher(cfg.Sampling, cfg.CacheMaxFlows, ingress, egress)
	if err != nil {
		return nil, err
	}

	return flowsAgent(cfg, informer, fetcher, exportFunc, agentIP)
}

// flowsAgent is a private constructor with injectable dependencies, usable for tests
func flowsAgent(cfg *config.AgentConfig,
	informer ifaces2.Informer,
	fetcher ebpfFlowFetcher,
	exporter node.TerminalFunc[[]*flow2.Record],
	agentIP net.IP,
) (*Flows, error) {
	// configure allow/deny interfaces filter
	filter, err := initInterfaceFilter(cfg.Interfaces, cfg.ExcludeInterfaces)
	if err != nil {
		return nil, fmt.Errorf("configuring interface filters: %w", err)
	}

	registerer := ifaces2.NewRegisterer(informer, cfg.BuffersLength)

	interfaceNamer := func(ifIndex int) string {
		iface, ok := registerer.IfaceNameForIndex(ifIndex)
		if !ok {
			return "unknown"
		}
		return iface
	}

	mapTracer := flow2.NewMapTracer(fetcher, cfg.CacheActiveTimeout)
	rbTracer := flow2.NewRingBufTracer(fetcher, mapTracer, cfg.CacheActiveTimeout)
	accounter := flow2.NewAccounter(
		cfg.CacheMaxFlows, cfg.CacheActiveTimeout, time.Now, monotime.Now)
	return &Flows{
		ebpf:           fetcher,
		exporter:       exporter,
		interfaces:     registerer,
		filter:         filter,
		cfg:            cfg,
		mapTracer:      mapTracer,
		rbTracer:       rbTracer,
		accounter:      accounter,
		agentIP:        agentIP,
		interfaceNamer: interfaceNamer,
	}, nil
}

func flowDirections(cfg *config.AgentConfig) (ingress, egress bool) {
	switch cfg.Direction {
	case DirectionIngress:
		return true, false
	case DirectionEgress:
		return false, true
	case DirectionBoth:
		return true, true
	default:
		alog().Warn("unknown DIRECTION. Tracing both ingress and egress traffic",
			"direction", cfg.Direction)
		return true, true
	}
}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (f *Flows) Run(ctx context.Context) error {
	alog := alog()
	f.status = StatusStarting
	alog.Info("starting Flows agent")
	graph, err := f.buildAndStartPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	graphDone := make(chan struct{})
	go func() {
		graph.Run()
		close(graphDone)
	}()

	f.status = StatusStarted
	alog.Info("Flows agent successfully started")
	<-ctx.Done()

	f.status = StatusStopping
	alog.Info("stopping Flows agent")
	if err := f.ebpf.Close(); err != nil {
		alog.Warn("eBPF resources not correctly closed", "error", err)
	}

	alog.Debug("waiting for all nodes to finish their pending work")
	<-graphDone

	f.status = StatusStopped
	alog.Info("Flows agent stopped")
	return nil
}

func (f *Flows) Status() Status {
	return f.status
}

// interfacesManager uses an informer to check new/deleted network interfaces. For each running
// interface, it registers a flow ebpfFetcher that will forward new flows to the returned channel
// TODO: consider move this method and "onInterfaceAdded" to another type
func (f *Flows) interfacesManager(ctx context.Context) error {
	slog := alog().With("function", "interfacesManager")

	slog.Debug("subscribing for network interface events")
	ifaceEvents, err := f.interfaces.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("instantiating interfaces' informer: %w", err)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				slog.Debug("stopping interfaces' listener")
				return
			case event := <-ifaceEvents:
				slog.Debug("received event", "event", event)
				switch event.Type {
				case ifaces2.EventAdded:
					f.onInterfaceAdded(event.Interface)
				case ifaces2.EventDeleted:
					// qdiscs, ingress and egress filters are automatically deleted so we don't need to
					// specifically detach them from the ebpfFetcher
				default:
					slog.Warn("unknown event type", "event", event)
				}
			}
		}
	}()

	return nil
}

func (f *Flows) onInterfaceAdded(iface ifaces2.Interface) {
	alog := alog().With("interface", iface)
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	if !f.filter.Allowed(iface.Name) {
		alog.Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	alog.Info("interface detected. Registering flow ebpfFetcher")
	if err := f.ebpf.Register(iface); err != nil {
		alog.Warn("can't register flow ebpfFetcher. Ignoring", "error", err)
		return
	}
}

func buildFlowExporter(_ *config.AgentConfig) (node.TerminalFunc[[]*flow2.Record], error) {
	return func(in <-chan []*flow2.Record) {
		for flows := range in {
			fmt.Printf("received %d flows\n", len(flows))
			for _, f := range flows {
				fmt.Printf("%#v\n", *f)
			}
		}
	}, nil
}
