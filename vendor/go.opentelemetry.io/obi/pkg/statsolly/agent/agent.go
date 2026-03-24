// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	stats "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/netip"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func alog() *slog.Logger {
	return slog.With("component", "agent.StatsO11y")
}

// Status of the agent service. Helps on the health report as well as making some asynchronous
// tests waiting for the agent to accept stats.
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

var errShutdownTimeout = errors.New("graceful shutdown has timed out while waiting for eBPF statsolly to finish")

// Stats reporting agent
type Stats struct {
	cfg     *obi.Config
	ctxInfo *global.ContextInfo
	graph   *swarm.Runner

	// elements used to decorate stats with extra information
	agentIP net.IP

	// stat metrics
	rbTracer *stats.RingBufTracer

	// focuses on TCP/UDP stack internals (kprobes/tracepoints)
	fetcher ebpFetcher

	status Status
}

type ebpFetcher interface {
	io.Closer
	StatsEventsMap() *ciliumebpf.Map
}

func StatsAgent(ctxInfo *global.ContextInfo, cfg *obi.Config) (*Stats, error) {
	alog := alog()
	alog.Info("initializing Stats agent")

	var (
		statsFetcher ebpFetcher
		err          error
	)

	alog.Debug("acquiring Agent IP")

	agentIP, err := netip.FetchAgentIP(cfg.Stats.AgentIP, string(cfg.Stats.AgentIPIface), cfg.Stats.AgentIPType)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}
	alog.Debug("agent IP: " + agentIP.String())

	statsFetcher, err = newFetcher()
	if err != nil {
		return nil, err
	}

	return statsAgent(ctxInfo, cfg, statsFetcher, agentIP)
}

func newFetcher() (ebpFetcher, error) {
	return ebpf.NewStatsFetcher()
}

// statsAgent is a private constructor with injectable dependencies, usable for tests
func statsAgent(
	ctxInfo *global.ContextInfo,
	cfg *obi.Config,
	statsFetcher ebpFetcher,
	agentIP net.IP,
) (*Stats, error) {
	rbTracer := stats.NewRingBufTracer(statsFetcher.StatsEventsMap(), &cfg.EBPF)

	return &Stats{
		ctxInfo:  ctxInfo,
		cfg:      cfg,
		rbTracer: rbTracer,
		agentIP:  agentIP,
		fetcher:  statsFetcher,
	}, nil
}

// Run a Stats agent
func (s *Stats) Run(ctx context.Context) error {
	alog := alog()

	s.status = StatusStarting
	alog.Info("starting Stats agent")

	graph, err := s.buildPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	s.graph = graph

	s.graph.Start(ctx, swarm.WithCancelTimeout(s.cfg.ShutdownTimeout))
	s.status = StatusStarted

	alog.Info("Stats agent successfully started")

	<-ctx.Done()

	if err := s.stop(); err != nil {
		return fmt.Errorf("failed to stop Stats agent: %w", err)
	}

	return nil
}

func (s *Stats) stop() error {
	alog := alog()

	stopped := make(chan error)
	go func() {
		s.status = StatusStopping
		alog.Info("stopping Stats agent")
		if err := s.fetcher.Close(); err != nil {
			alog.Warn("eBPF resources not correctly closed", "error", err)
		}

		alog.Debug("waiting for all nodes to finish their pending work")

		err := <-s.graph.Done()

		s.status = StatusStopped

		stopped <- err

		close(stopped)

		alog.Info("Stats agent stopped")
	}()

	select {
	case <-time.After(s.cfg.ShutdownTimeout):
		return errShutdownTimeout
	case err := <-stopped:
		// err might be nil
		return err
	}
}

func (s *Stats) Status() Status {
	return s.status
}
