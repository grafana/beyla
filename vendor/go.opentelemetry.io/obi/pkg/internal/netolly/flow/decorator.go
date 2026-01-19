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

package flow // import "go.opentelemetry.io/obi/pkg/internal/netolly/flow"

import (
	"context"
	"net"

	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

type InterfaceNamer func(ifIndex int) string

// Decorate the flows with extra metadata fields that are not directly fetched by eBPF
// or by any previous pipeline stage (DNS, Kubernetes...):
// - The interface name (corresponding to the interface index in the flow).
// - The IP address of the agent host.
// - If there is no source or destination hostname, the source IP and destination
func Decorate(agentIP net.IP, ifaceNamer InterfaceNamer, input *msg.Queue[[]*ebpf.Record], output *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	ip := agentIP.String()
	in := input.Subscribe(msg.SubscriberName("flow.Decorate"))
	return func(ctx context.Context) {
		defer output.Close()
		swarms.ForEachInput(ctx, in, nil, func(flows []*ebpf.Record) {
			for _, flow := range flows {
				flow.Attrs.Interface = ifaceNamer(int(flow.Id.IfIndex))
				flow.Attrs.OBIIP = ip
				if flow.Attrs.DstName == "" {
					flow.Attrs.DstName = flow.Id.DstIP().IP().String()
				}
				if flow.Attrs.SrcName == "" {
					flow.Attrs.SrcName = flow.Id.SrcIP().IP().String()
				}
			}
			output.Send(flows)
		})
	}
}
