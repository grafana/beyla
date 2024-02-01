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
	"net"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

type InterfaceNamer func(ifIndex int) string

// Decorate adds to the flows extra metadata fields that are not directly fetched by eBPF:
// - The interface name (corresponding to the interface index in the flow).
// - The IP address of the agent host.
func Decorate(agentIP net.IP, ifaceNamer InterfaceNamer) func(in <-chan []*ebpf.Record, out chan<- []*ebpf.Record) {
	ip := agentIP.String()
	return func(in <-chan []*ebpf.Record, out chan<- []*ebpf.Record) {
		for flows := range in {
			for _, flow := range flows {
				flow.Interface = ifaceNamer(int(flow.Id.IfIndex))
				flow.AgentIP = ip
			}
			out <- flows
		}
	}
}
