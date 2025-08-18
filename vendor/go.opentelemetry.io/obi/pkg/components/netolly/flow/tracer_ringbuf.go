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

package flow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	ebpfcommon "go.opentelemetry.io/obi/pkg/components/ebpf/common"
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/components/kube"
	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/netolly/rdns"
	"go.opentelemetry.io/obi/pkg/components/netolly/transform/cidr"
	"go.opentelemetry.io/obi/pkg/components/netolly/transform/k8s"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rtlog() *slog.Logger {
	return slog.With("component", "flow.RingBufTracer")
}

type RingBufTracer struct {
	cfg           *obi.Config
	flowFetcher   ebpf.FlowFetcher
	k8sInformer   *kube.MetadataProvider
	k8sDecorator  *k8s.Decorator
	rdnsEnricher  *rdns.ReverseDNSEnricher
	cidrDecorator *cidr.CIDRDecorator
	flowDecorator *FlowDecorator
	flowFilter    *filter.ElementFilter[*ebpf.Record]
	rec           *ebpf.Record
}

func NewRingBufTracer(fetcher ebpf.FlowFetcher,
	cfg *obi.Config,
	k8sInformer *kube.MetadataProvider,
	agentIP string,
	ifaceNamer InterfaceNamer,
) (*RingBufTracer, error) {
	flowFilter, err := filter.NewElementFilter[*ebpf.Record](cfg.Filters.Network,
		nil, cfg.Attributes.ExtraGroupAttributes, ebpf.RecordStringGetters)
	if err != nil {
		return nil, fmt.Errorf("error instantiating flow filter: %w", err)
	}

	return &RingBufTracer{
		cfg:           cfg,
		flowFetcher:   fetcher,
		k8sInformer:   k8sInformer,
		flowDecorator: NewFlowDecorator(agentIP, ifaceNamer),
		flowFilter:    flowFilter,
		rec:           &ebpf.Record{},
	}, nil
}

func (m *RingBufTracer) ringbufferLoop(ctx context.Context, out *msg.Queue[ebpf.Record]) {
	defer out.MarkCloseable()

	rtlog := rtlog()

	var err error
	m.k8sDecorator, err = k8s.NewDecorator(ctx, &m.cfg.Attributes.Kubernetes, m.k8sInformer)
	if err != nil {
		rtlog.Error("error creating k8s decorator", "error", err)
		return
	}

	m.rdnsEnricher, err = rdns.NewReverseDNSEnricher(ctx, &m.cfg.NetworkFlows.ReverseDNS)
	if err != nil {
		rtlog.Error("error creating rdns enricher", "error", err)
		return
	}

	m.cidrDecorator, err = cidr.NewCIDRDecorator(m.cfg.NetworkFlows.CIDRs)
	if err != nil {
		rtlog.Error("error creating CIDR decorator ", "error", err)
		return
	}

	var rec ringbuf.Record

	for {
		select {
		case <-ctx.Done():
			rtlog.Debug("exiting trace loop due to context cancellation")
			return
		default:
			if err := m.flowFetcher.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					rtlog.Debug("Received signal, exiting..")
					return
				}

				rtlog.Warn("ignoring flow event", "error", err)
				continue
			}

			event, err := ebpfcommon.ReinterpretCast[ebpf.NetFlowRecordT](rec.RawSample)
			if err != nil {
				continue
			}

			m.handleEvent(event, out)
		}
	}
}

func (m *RingBufTracer) handleEvent(event *ebpf.NetFlowRecordT, out *msg.Queue[ebpf.Record]) {
	*m.rec = ebpf.Record{NetFlowRecordT: *event}

	if !m.k8sDecorator.Decorate(m.rec) {
		return
	}

	m.rdnsEnricher.Enrich(m.rec)
	m.cidrDecorator.Decorate(m.rec)
	m.flowDecorator.Decorate(m.rec)

	if !m.flowFilter.Allow(m.rec) {
		return
	}

	out.Send(*m.rec)
}

func (m *RingBufTracer) TraceLoop(out *msg.Queue[ebpf.Record]) swarm.RunFunc {
	return func(ctx context.Context) {
		m.ringbufferLoop(ctx, out)
	}
}
