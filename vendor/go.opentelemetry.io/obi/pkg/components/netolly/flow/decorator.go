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
	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
)

type InterfaceNamer func(ifIndex int) string

// FlowDecorator the flows with extra metadata fields that are not directly fetched by eBPF
// or by any previous pipeline stage (DNS, Kubernetes...):
// - The interface name (corresponding to the interface index in the flow).
// - The IP address of the agent host.
// - If there is no source or destination hostname, the source IP and destination
type FlowDecorator struct {
	agentIP    string
	ifaceNamer InterfaceNamer
}

func NewFlowDecorator(agentIP string, ifaceNamer InterfaceNamer) *FlowDecorator {
	return &FlowDecorator{
		agentIP:    agentIP,
		ifaceNamer: ifaceNamer,
	}
}

func (d *FlowDecorator) Decorate(flow *ebpf.Record) {
	flow.Attrs.Interface = d.ifaceNamer(int(flow.Id.IfIndex))
	flow.Attrs.OBIIP = d.agentIP
	if flow.Attrs.Dst.TargetName == "" {
		flow.Attrs.Dst.TargetName = flow.DstIP().IP().String()
	}
	if flow.Attrs.Src.TargetName == "" {
		flow.Attrs.Src.TargetName = flow.SrcIP().IP().String()
	}
}
